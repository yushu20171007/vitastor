// Copyright (c) Vitaliy Filippov, 2019+
// License: VNPL-1.1 or GNU GPL-2.0+ (see README.md for details)

// Short io_uring send handling in osd_messenger_t: the unsent tail is resent
// without zerocopy and every send_free range is released exactly once, after
// both the tail is sent and the zerocopy release notification arrives.

#undef NDEBUG
#include <assert.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <unistd.h>

#include <deque>
#include <vector>

#include "messenger.h"

#define TEST_DATA_LEN 4096
#define TEST_BATCH_LEN (OSD_PACKET_SIZE + TEST_DATA_LEN)

// Records SQEs and delivers completions by hand, with the same prev/more
// semantics as ring_loop_t::loop()
class send_ring_t: public ring_loop_i
{
    // Every submit stores &cl->write_msg in the SQE. Copy the iovec at submit
    // time so a later send cannot rewrite what an earlier SQE observed.
    struct captured_msg_t
    {
        bool captured = false;
        msghdr msg = {};
        std::vector<iovec> iov;
    };

public:
    std::deque<io_uring_sqe> sqes;
    std::deque<ring_data_t> datas;
    std::deque<captured_msg_t> captured;

    void register_consumer(ring_consumer_t *consumer) override {}
    void unregister_consumer(ring_consumer_t *consumer) override {}
    int register_eventfd() override { return -1; }
    io_uring_sqe* get_sqe() override
    {
        sqes.emplace_back();
        datas.emplace_back();
        io_uring_sqe *sqe = &sqes.back();
        ring_data_t *d = &datas.back();
        *sqe = {};
        d->res = 0;
        d->prev = d->more = false;
        io_uring_sqe_set_data(sqe, d);
        captured.emplace_back();
        return sqe;
    }

    // Call after every try_send / send_replies that may have submitted an SQE,
    // before handle_send mutates send_list or the next send reuses write_msg.
    void snapshot()
    {
        assert(captured.size() == sqes.size());
        for (size_t i = 0; i < sqes.size(); i++)
        {
            if (captured[i].captured)
                continue;
            assert(sqes[i].opcode == IORING_OP_SENDMSG_ZC || sqes[i].opcode == IORING_OP_SENDMSG);
            msghdr *live = (msghdr*)sqes[i].addr;
            assert(live && live->msg_iov && live->msg_iovlen > 0);
            captured[i].iov.assign(live->msg_iov, live->msg_iov + live->msg_iovlen);
            captured[i].msg = *live;
            captured[i].msg.msg_iov = captured[i].iov.data();
            captured[i].msg.msg_iovlen = captured[i].iov.size();
            captured[i].captured = true;
        }
    }
    void set_immediate(const std::function<void()> & cb) override { cb(); }
    int submit() override { return 0; }
    int wait() override { return 0; }
    unsigned space_left() override { return 1024; }
    bool has_work() override { return false; }
    bool has_sendmsg_zc() override { return true; }
    void loop() override {}
    void wakeup() override {}
    unsigned save() override { return 0; }
    void restore(unsigned sqe_tail) override {}

    // more = true emulates a CQE with IORING_CQE_F_MORE (first zerocopy completion)
    void complete(size_t i, int res, bool more)
    {
        assert(i < datas.size());
        assert((ring_data_t*)(uintptr_t)sqes[i].user_data == &datas[i]);
        ring_data_t *d = &datas[i];
        assert(d->callback);
        if (more)
        {
            d->res = res;
            d->more = true;
            d->callback(d);
            d->prev = true;
            d->more = false;
        }
        else
        {
            ring_data_t dl;
            dl.iov = d->iov;
            dl.res = res;
            dl.more = false;
            dl.prev = d->prev;
            dl.callback.swap(d->callback);
            d->prev = false;
            dl.callback(&dl);
        }
    }

    bool is_zc(size_t i)
    {
        assert(i < sqes.size());
        assert(sqes[i].opcode == IORING_OP_SENDMSG_ZC || sqes[i].opcode == IORING_OP_SENDMSG);
        return sqes[i].opcode == IORING_OP_SENDMSG_ZC;
    }

    msghdr *msg(size_t i)
    {
        assert(i < captured.size() && captured[i].captured);
        return &captured[i].msg;
    }
};

class test_msgr_t: public osd_messenger_t
{
public:
    void set_zerocopy(bool enabled)
    {
        min_zerocopy_send_size = enabled ? 0 : -1;
    }

    void set_sync(bool enabled)
    {
        use_sync_send_recv = enabled;
    }

    // peer_fd, when set, receives the other end of the socketpair.
    // nonblock is required for the sync send path, which calls sendmsg directly.
    osd_client_t *add_client(int *peer_fd = NULL, bool nonblock = false)
    {
        int fds[2];
        int r = socketpair(AF_UNIX, SOCK_STREAM | (nonblock ? SOCK_NONBLOCK : 0), 0, fds);
        assert(r == 0);
        if (peer_fd)
            *peer_fd = fds[1];
        else
            close(fds[1]);
        osd_client_t *cl = new osd_client_t();
        cl->client_id = next_client_id++;
        cl->peer_fd = fds[0];
        cl->peer_state = PEER_CONNECTED;
        clients[cl->client_id] = cl;
        clients_by_fd[cl->peer_fd] = cl;
        return cl;
    }

    // Reply to a SEC_READ with TEST_DATA_LEN bytes of data, sent from op->buf.
    // Not queued: push_reply / outbox_push decide how it enters the send path.
    osd_op_t *make_reply(osd_client_t *cl, uint8_t fill)
    {
        osd_op_t *op = new osd_op_t();
        op->op_type = OSD_OP_IN;
        op->client_id = cl->client_id;
        op->req.hdr.opcode = OSD_OP_SEC_READ;
        op->reply.hdr.magic = SECONDARY_OSD_REPLY_MAGIC;
        op->reply.hdr.opcode = OSD_OP_SEC_READ;
        op->reply.hdr.retval = TEST_DATA_LEN;
        op->buf = malloc_or_die(TEST_DATA_LEN);
        memset(op->buf, fill, TEST_DATA_LEN);
        op->iov.push_back(op->buf, TEST_DATA_LEN);
        return op;
    }

    osd_op_t *push_reply(osd_client_t *cl, uint8_t fill)
    {
        osd_op_t *op = make_reply(cl, fill);
        cl->write_ops.push_back(op);
        return op;
    }

    bool send(osd_client_t *cl)
    {
        bool ok = try_send(cl);
        static_cast<send_ring_t*>(ringloop)->snapshot();
        return ok;
    }

    // What the ring consumer does after a completion or EPOLLOUT: flush the
    // write_ready queue, then freeze any SQE that flush submitted.
    void send_queued()
    {
        send_replies();
        static_cast<send_ring_t*>(ringloop)->snapshot();
    }

    bool is_write_ready(osd_client_t *cl)
    {
        for (auto id: write_ready_clients)
            if (id == cl->client_id)
                return true;
        return false;
    }

    void socket_writable(osd_client_t *cl)
    {
        handle_peer_epoll(cl->peer_fd, EPOLLOUT);
    }
};

struct test_env_t
{
    timerfd_manager_t *tfd;
    send_ring_t *ring;
    test_msgr_t *msgr;
    std::map<int, bool> fd_write_watched;

    bool write_watched(int fd)
    {
        auto it = fd_write_watched.find(fd);
        return it != fd_write_watched.end() && it->second;
    }

    test_env_t(bool zerocopy)
    {
        tfd = new timerfd_manager_t([this](int fd, bool wr, std::function<void(int, int)> callback)
        {
            if (callback)
                fd_write_watched[fd] = wr;
            else
                fd_write_watched.erase(fd);
        });
        ring = new send_ring_t();
        msgr = new test_msgr_t();
        msgr->tfd = tfd;
        msgr->ringloop = ring;
        msgr->has_sendmsg_zc = true;
        msgr->set_zerocopy(zerocopy);
    }

    ~test_env_t()
    {
        delete msgr;
        delete ring;
        delete tfd;
    }
};

// refs is a string of '1'/'0', one per remaining send_free entry, meaning
// whether MSGR_SENDP_REF is still set. NULL requires every remaining entry
// to still be referenced: a non-head entry whose REF was cleared early stays
// in the deque and would otherwise look like a successful hold.
static void check_released(osd_client_t *cl, uint64_t next_send_free, size_t send_free_size, const char *refs = NULL)
{
    if (cl->next_send_free != next_send_free || cl->send_free.size() != send_free_size)
    {
        fprintf(stderr, "send_free: expected next=%ju size=%zu, got next=%ju size=%zu\n",
            next_send_free, send_free_size, cl->next_send_free, cl->send_free.size());
        abort();
    }
    if (refs)
        assert(strlen(refs) == send_free_size);
    for (size_t i = 0; i < cl->send_free.size(); i++)
    {
        bool on = cl->send_free[i].flags & MSGR_SENDP_REF;
        bool expect = refs ? refs[i] == '1' : true;
        if (on != expect)
        {
            fprintf(stderr, "send_free[%zu] REF=%d, expected %d\n", i, (int)on, (int)expect);
            abort();
        }
    }
}

static size_t msg_bytes(msghdr *msg)
{
    size_t total = 0;
    for (size_t j = 0; j < msg->msg_iovlen; j++)
        total += msg->msg_iov[j].iov_len;
    return total;
}

static void check_tail(send_ring_t *ring, size_t i, osd_op_t *op, size_t sent)
{
    assert(!ring->is_zc(i));
    assert(ring->sqes[i].msg_flags & MSG_WAITALL);
    msghdr *msg = ring->msg(i);
    assert(msg_bytes(msg) == TEST_BATCH_LEN - sent);
    assert(sent >= OSD_PACKET_SIZE);
    assert(msg->msg_iov[0].iov_base == (uint8_t*)op->buf + (sent - OSD_PACKET_SIZE));
}

// Short send that ends inside the header: the first iov is shrunk, not dropped
static void check_partial_header(send_ring_t *ring, size_t i, osd_op_t *op, size_t sent)
{
    assert(sent > 0 && sent < OSD_PACKET_SIZE);
    assert(!ring->is_zc(i));
    assert(ring->sqes[i].msg_flags & MSG_WAITALL);
    msghdr *msg = ring->msg(i);
    assert(msg->msg_iovlen == 2);
    assert(msg->msg_iov[0].iov_base == op->reply.buf + sent);
    assert(msg->msg_iov[0].iov_len == OSD_PACKET_SIZE - sent);
    assert(msg->msg_iov[1].iov_base == op->buf);
    assert(msg->msg_iov[1].iov_len == TEST_DATA_LEN);
    assert(msg_bytes(msg) == TEST_BATCH_LEN - sent);
}

// Zerocopy short write, the tail is sent before the release notification arrives
static void test_zc_tail_before_notify()
{
    printf("test_zc_tail_before_notify\n");
    test_env_t env(true);
    osd_client_t *cl = env.msgr->add_client();
    osd_op_t *a = env.msgr->push_reply(cl, 0xaa);
    env.msgr->send(cl);
    assert(env.ring->is_zc(0));
    env.ring->complete(0, 1000, true);
    assert(cl->send_plain_tail);
    assert(cl->send_tail_zc_pending);
    assert(cl->send_list_size == TEST_BATCH_LEN - 1000);
    assert(env.msgr->is_write_ready(cl));
    env.msgr->send_queued();
    check_tail(env.ring, 1, a, 1000);
    // The original SQE must still describe the full batch after the tail submit
    assert(env.ring->msg(0)->msg_iovlen == 2);
    assert(env.ring->msg(0)->msg_iov[0].iov_base == &a->reply);
    assert(msg_bytes(env.ring->msg(0)) == TEST_BATCH_LEN);
    env.ring->complete(1, TEST_BATCH_LEN - 1000, false);
    assert(!cl->send_plain_tail);
    // The zerocopy prefix is still owned by the kernel
    check_released(cl, 0, 1);
    env.ring->complete(0, 0, false);
    check_released(cl, 1, 0);
}

// Zerocopy short write, the release notification arrives before the tail is sent
static void test_zc_notify_before_tail()
{
    printf("test_zc_notify_before_tail\n");
    test_env_t env(true);
    osd_client_t *cl = env.msgr->add_client();
    osd_op_t *a = env.msgr->push_reply(cl, 0xaa);
    env.msgr->send(cl);
    env.ring->complete(0, 1000, true);
    // Notification before the tail is even submitted
    env.ring->complete(0, 0, false);
    assert(!cl->send_tail_zc_pending);
    check_released(cl, 0, 1);
    env.msgr->send_queued();
    check_tail(env.ring, 1, a, 1000);
    check_released(cl, 0, 1);
    env.ring->complete(1, TEST_BATCH_LEN - 1000, false);
    check_released(cl, 1, 0);
}

// A notification of an older zerocopy batch arrives while the tail is pending.
// It must be released at once and must not swallow the notification of the short batch.
static void test_zc_other_notify_during_tail()
{
    printf("test_zc_other_notify_during_tail\n");
    test_env_t env(true);
    osd_client_t *cl = env.msgr->add_client();
    env.msgr->push_reply(cl, 0x11);
    env.msgr->send(cl);
    env.ring->complete(0, TEST_BATCH_LEN, true);
    osd_op_t *a = env.msgr->push_reply(cl, 0xaa);
    env.msgr->send(cl);
    assert(env.ring->is_zc(1));
    env.ring->complete(1, 1000, true);
    assert(cl->send_tail_from == 1 && cl->send_tail_to == 2);
    env.msgr->send_queued();
    check_tail(env.ring, 2, a, 1000);
    env.ring->complete(0, 0, false);
    check_released(cl, 1, 1);
    env.ring->complete(1, 0, false);
    check_released(cl, 1, 1);
    env.ring->complete(2, TEST_BATCH_LEN - 1000, false);
    check_released(cl, 2, 0);
}

// Copying short write while an older zerocopy notification is still in flight
static void test_plain_short_with_zc_notify()
{
    printf("test_plain_short_with_zc_notify\n");
    test_env_t env(true);
    osd_client_t *cl = env.msgr->add_client();
    env.msgr->push_reply(cl, 0x11);
    env.msgr->send(cl);
    assert(env.ring->is_zc(0));
    env.ring->complete(0, TEST_BATCH_LEN, true);
    env.msgr->set_zerocopy(false);
    osd_op_t *a = env.msgr->push_reply(cl, 0xaa);
    env.msgr->send(cl);
    assert(!env.ring->is_zc(1));
    env.ring->complete(1, 1000, false);
    assert(cl->send_plain_tail);
    assert(!cl->send_tail_zc_pending);
    env.msgr->send_queued();
    check_tail(env.ring, 2, a, 1000);
    env.ring->complete(0, 0, false);
    check_released(cl, 1, 1);
    env.ring->complete(2, TEST_BATCH_LEN - 1000, false);
    check_released(cl, 2, 0);
}

// The tail itself is short-written again: the owner range must be kept
static void test_tail_short_again()
{
    printf("test_tail_short_again\n");
    test_env_t env(true);
    osd_client_t *cl = env.msgr->add_client();
    osd_op_t *a = env.msgr->push_reply(cl, 0xaa);
    env.msgr->send(cl);
    env.ring->complete(0, 1000, true);
    env.msgr->send_queued();
    check_tail(env.ring, 1, a, 1000);
    env.ring->complete(1, 1000, false);
    assert(cl->send_plain_tail);
    assert(cl->send_tail_from == 0 && cl->send_tail_to == 1);
    assert(cl->send_tail_zc_pending);
    env.msgr->send_queued();
    check_tail(env.ring, 2, a, 2000);
    env.ring->complete(0, 0, false);
    check_released(cl, 0, 1);
    env.ring->complete(2, TEST_BATCH_LEN - 2000, false);
    check_released(cl, 1, 0);
}

// io_uring returns -EAGAIN: nothing was queued, so the batch waits for EPOLLOUT
// and is then resent through the copying tail path. A second EAGAIN does not
// submit another SQE until the socket is writable again.
static void test_eagain_resend()
{
    printf("test_eagain_resend\n");
    test_env_t env(true);
    osd_client_t *cl = env.msgr->add_client();
    osd_op_t *a = env.msgr->push_reply(cl, 0xaa);
    env.msgr->send(cl);
    assert(env.ring->is_zc(0));
    env.ring->complete(0, -EAGAIN, false);
    assert(env.msgr->clients.find(cl->client_id) != env.msgr->clients.end());
    assert(cl->send_plain_tail);
    assert(!cl->send_tail_zc_pending);
    assert(cl->send_list_size == TEST_BATCH_LEN);
    assert(!cl->write_ready);
    assert(env.fd_write_watched[cl->peer_fd]);
    assert(!env.msgr->is_write_ready(cl));
    env.msgr->send_queued();
    assert(env.ring->sqes.size() == 1);
    env.msgr->socket_writable(cl);
    assert(cl->write_ready);
    assert(!env.fd_write_watched[cl->peer_fd]);
    assert(env.msgr->is_write_ready(cl));
    env.msgr->send_queued();
    assert(env.ring->sqes.size() == 2);
    assert(!env.ring->is_zc(1));
    assert(env.ring->msg(1)->msg_iov[0].iov_base == &a->reply);
    env.ring->complete(1, -EAGAIN, false);
    assert(!cl->write_ready);
    assert(env.fd_write_watched[cl->peer_fd]);
    assert(!env.msgr->is_write_ready(cl));
    env.msgr->send_queued();
    assert(env.ring->sqes.size() == 2);
    env.msgr->socket_writable(cl);
    assert(!env.fd_write_watched[cl->peer_fd]);
    env.msgr->send_queued();
    assert(env.ring->sqes.size() == 3);
    env.ring->complete(2, TEST_BATCH_LEN, false);
    assert(!cl->send_plain_tail);
    check_released(cl, 1, 0);
}

// Failed zerocopy send: -EAGAIN carries IORING_CQE_F_MORE. The release
// notification must not free the buffer, and the resend still waits for EPOLLOUT.
static void test_eagain_zc_more()
{
    printf("test_eagain_zc_more\n");
    test_env_t env(true);
    osd_client_t *cl = env.msgr->add_client();
    osd_op_t *a = env.msgr->push_reply(cl, 0xaa);
    env.msgr->send(cl);
    assert(env.ring->is_zc(0));
    env.ring->complete(0, -EAGAIN, true);
    assert(cl->send_plain_tail);
    assert(cl->send_tail_zc_pending);
    assert(!cl->write_ready);
    assert(cl->send_list_size == TEST_BATCH_LEN);
    env.ring->complete(0, 0, false);
    assert(!cl->send_tail_zc_pending);
    check_released(cl, 0, 1);
    assert(env.ring->sqes.size() == 1);
    env.msgr->socket_writable(cl);
    env.msgr->send_queued();
    assert(!env.ring->is_zc(1));
    assert(env.ring->msg(1)->msg_iov[0].iov_base == &a->reply);
    env.ring->complete(1, TEST_BATCH_LEN, false);
    assert(!cl->send_plain_tail);
    check_released(cl, 1, 0);
}

// A zero-byte send without an error is still a broken socket
static void test_zero_bytes_disconnects()
{
    printf("test_zero_bytes_disconnects\n");
    test_env_t env(false);
    osd_client_t *cl = env.msgr->add_client();
    uint64_t client_id = cl->client_id;
    env.msgr->push_reply(cl, 0xaa);
    env.msgr->send(cl);
    env.ring->complete(0, 0, false);
    assert(env.msgr->clients.find(client_id) == env.msgr->clients.end());
}

// New replies that arrive after send_replies has already submitted the tail
// must not join that SQE. try_send returns immediately while it is in flight,
// and the tail completion has to queue the client again.
static void test_new_ops_wait_for_tail()
{
    printf("test_new_ops_wait_for_tail\n");
    test_env_t env(true);
    osd_client_t *cl = env.msgr->add_client();
    osd_op_t *a = env.msgr->push_reply(cl, 0xaa);
    env.msgr->send(cl);
    env.ring->complete(0, 1000, true);
    assert(env.msgr->is_write_ready(cl));
    env.msgr->send_queued();
    check_tail(env.ring, 1, a, 1000);
    assert(env.ring->sqes.size() == 2);
    assert(!env.msgr->is_write_ready(cl));
    assert(cl->write_state == 0);
    assert(cl->write_msg.msg_iovlen > 0);
    osd_op_t *b = env.msgr->make_reply(cl, 0xbb);
    cl->received_ops.push_back(b);
    env.msgr->outbox_push(b);
    assert(cl->write_ops.size() == 1);
    assert(cl->received_ops.empty());
    assert(env.ring->sqes.size() == 2);
    assert(!env.msgr->is_write_ready(cl));
    env.ring->complete(1, TEST_BATCH_LEN - 1000, false);
    assert(env.msgr->is_write_ready(cl));
    env.msgr->send_queued();
    assert(env.ring->sqes.size() == 3);
    assert(env.ring->is_zc(2));
    assert(env.ring->msg(2)->msg_iov[0].iov_base == &b->reply);
    env.ring->complete(2, TEST_BATCH_LEN, true);
    env.ring->complete(2, 0, false);
    // Batch 0 is still referenced and blocks the head. Batch 1's notification
    // cleared REF but the entry stays until the head is released.
    check_released(cl, 0, 2, "10");
    env.ring->complete(0, 0, false);
    check_released(cl, 2, 0);
}

// A spurious EPOLLOUT while a normal io_uring send is in flight must not
// enqueue the client into write_ready_clients
static void test_inflight_epollout_ignored()
{
    printf("test_inflight_epollout_ignored\n");
    test_env_t env(true);
    osd_client_t *cl = env.msgr->add_client();
    env.msgr->push_reply(cl, 0xaa);
    env.msgr->send(cl);
    assert(cl->write_msg.msg_iovlen > 0);
    assert(cl->send_list.size() > 0);
    env.msgr->socket_writable(cl);
    assert(!env.msgr->is_write_ready(cl));
    env.ring->complete(0, TEST_BATCH_LEN, true);
    env.ring->complete(0, 0, false);
    check_released(cl, 1, 0);
}

// -EINTR queued nothing, same as a zero-byte short send, but the socket is
// still writable: resubmit immediately and do not arm EPOLLOUT.
static void test_eintr_resend()
{
    printf("test_eintr_resend\n");
    test_env_t env(true);
    osd_client_t *cl = env.msgr->add_client();
    osd_op_t *a = env.msgr->push_reply(cl, 0xaa);
    env.msgr->send(cl);
    assert(env.ring->is_zc(0));
    env.ring->complete(0, -EINTR, false);
    assert(env.msgr->clients.find(cl->client_id) != env.msgr->clients.end());
    assert(cl->send_plain_tail);
    assert(!cl->send_tail_zc_pending);
    assert(cl->send_list_size == TEST_BATCH_LEN);
    assert(cl->write_ready);
    assert(!env.write_watched(cl->peer_fd));
    assert(env.msgr->is_write_ready(cl));
    assert(env.ring->sqes.size() == 1);
    env.msgr->send_queued();
    assert(env.ring->sqes.size() == 2);
    assert(!env.ring->is_zc(1));
    assert(env.ring->msg(1)->msg_iov[0].iov_base == &a->reply);
    assert(msg_bytes(env.ring->msg(1)) == TEST_BATCH_LEN);
    env.ring->complete(1, TEST_BATCH_LEN, false);
    assert(!cl->send_plain_tail);
    check_released(cl, 1, 0);
}

// Zerocopy -EINTR with IORING_CQE_F_MORE. The notification must not free the
// buffer, and unlike -EAGAIN the tail is submitted without waiting for EPOLLOUT.
static void test_eintr_zc_more()
{
    printf("test_eintr_zc_more\n");
    test_env_t env(true);
    osd_client_t *cl = env.msgr->add_client();
    osd_op_t *a = env.msgr->push_reply(cl, 0xaa);
    env.msgr->send(cl);
    assert(env.ring->is_zc(0));
    env.ring->complete(0, -EINTR, true);
    assert(cl->send_plain_tail);
    assert(cl->send_tail_zc_pending);
    assert(cl->write_ready);
    assert(!env.write_watched(cl->peer_fd));
    assert(cl->send_list_size == TEST_BATCH_LEN);
    assert(env.msgr->is_write_ready(cl));
    env.ring->complete(0, 0, false);
    assert(!cl->send_tail_zc_pending);
    check_released(cl, 0, 1);
    assert(env.ring->sqes.size() == 1);
    env.msgr->send_queued();
    assert(env.ring->sqes.size() == 2);
    assert(!env.ring->is_zc(1));
    assert(env.ring->msg(1)->msg_iov[0].iov_base == &a->reply);
    assert(msg_bytes(env.ring->msg(1)) == TEST_BATCH_LEN);
    env.ring->complete(1, TEST_BATCH_LEN, false);
    assert(!cl->send_plain_tail);
    check_released(cl, 1, 0);
}

// Positive short write, then the copying tail itself completes with -EAGAIN.
// The owner range stays, and EPOLLOUT resends from the same offset.
static void test_tail_eagain()
{
    printf("test_tail_eagain\n");
    test_env_t env(true);
    osd_client_t *cl = env.msgr->add_client();
    osd_op_t *a = env.msgr->push_reply(cl, 0xaa);
    env.msgr->send(cl);
    env.ring->complete(0, 1000, true);
    assert(cl->send_tail_from == 0 && cl->send_tail_to == 1);
    assert(cl->send_tail_zc_pending);
    env.msgr->send_queued();
    check_tail(env.ring, 1, a, 1000);
    env.ring->complete(1, -EAGAIN, false);
    assert(cl->send_plain_tail);
    assert(cl->send_tail_from == 0 && cl->send_tail_to == 1);
    assert(cl->send_tail_zc_pending);
    assert(cl->send_list_size == TEST_BATCH_LEN - 1000);
    assert(!cl->write_ready);
    assert(env.write_watched(cl->peer_fd));
    assert(!env.msgr->is_write_ready(cl));
    env.msgr->send_queued();
    assert(env.ring->sqes.size() == 2);
    env.msgr->socket_writable(cl);
    assert(cl->write_ready);
    assert(!env.write_watched(cl->peer_fd));
    assert(env.msgr->is_write_ready(cl));
    env.msgr->send_queued();
    assert(env.ring->sqes.size() == 3);
    check_tail(env.ring, 2, a, 1000);
    env.ring->complete(2, TEST_BATCH_LEN - 1000, false);
    assert(!cl->send_plain_tail);
    check_released(cl, 0, 1);
    env.ring->complete(0, 0, false);
    check_released(cl, 1, 0);
}

// A zero-byte zerocopy completion that is not -EAGAIN/-EINTR still disconnects.
// MORE means the notification is still owed, so the client and its buffer stay
// until that CQE arrives, and the buffer is released once.
static void test_zero_zc_disconnects()
{
    printf("test_zero_zc_disconnects\n");
    test_env_t env(true);
    osd_client_t *cl = env.msgr->add_client();
    uint64_t client_id = cl->client_id;
    env.msgr->push_reply(cl, 0xaa);
    env.msgr->send(cl);
    assert(env.ring->is_zc(0));
    env.ring->complete(0, 0, true);
    assert(env.msgr->clients.find(client_id) != env.msgr->clients.end());
    assert(cl->peer_state == PEER_STOPPED);
    assert(cl->refs == 1);
    check_released(cl, 0, 1);
    env.ring->complete(0, 0, false);
    assert(env.msgr->clients.find(client_id) == env.msgr->clients.end());
}

// Fewer bytes than the header: only the first iov is shrunk.
static void test_short_inside_header()
{
    printf("test_short_inside_header\n");
    test_env_t env(true);
    osd_client_t *cl = env.msgr->add_client();
    osd_op_t *a = env.msgr->push_reply(cl, 0xaa);
    env.msgr->send(cl);
    env.ring->complete(0, 10, true);
    assert(cl->send_plain_tail);
    assert(cl->send_tail_zc_pending);
    assert(cl->send_list_size == TEST_BATCH_LEN - 10);
    env.msgr->send_queued();
    check_partial_header(env.ring, 1, a, 10);
    env.ring->complete(1, TEST_BATCH_LEN - 10, false);
    assert(!cl->send_plain_tail);
    check_released(cl, 0, 1);
    env.ring->complete(0, 0, false);
    check_released(cl, 1, 0);
}

// EPOLLOUT while the copying tail SQE is still in flight must not enqueue
// another send. msg_iovlen > 0 is the in-flight mark.
static void test_inflight_tail_epollout_ignored()
{
    printf("test_inflight_tail_epollout_ignored\n");
    test_env_t env(true);
    osd_client_t *cl = env.msgr->add_client();
    env.msgr->push_reply(cl, 0xaa);
    env.msgr->send(cl);
    env.ring->complete(0, 1000, true);
    env.msgr->send_queued();
    assert(env.ring->sqes.size() == 2);
    assert(cl->send_plain_tail);
    assert(cl->write_msg.msg_iovlen > 0);
    assert(cl->write_state == 0);
    assert(cl->write_ready);
    assert(!env.msgr->is_write_ready(cl));
    env.msgr->socket_writable(cl);
    assert(!env.msgr->is_write_ready(cl));
    assert(cl->write_state == 0);
    assert(env.ring->sqes.size() == 2);
    assert(!env.write_watched(cl->peer_fd));
    env.ring->complete(1, TEST_BATCH_LEN - 1000, false);
    env.ring->complete(0, 0, false);
    check_released(cl, 1, 0);
}

static void read_exact(int fd, uint8_t *buf, size_t n)
{
    size_t got = 0;
    while (got < n)
    {
        ssize_t r = recv(fd, buf + got, n - got, 0);
        assert(r > 0);
        got += r;
    }
}

// use_sync_send_recv: a full socket buffer stops the retry loop, arms EPOLLOUT,
// and the writable edge continues from the unsent bytes. No io_uring SQE.
static void test_sync_eagain_epollout()
{
    printf("test_sync_eagain_epollout\n");
    test_env_t env(false);
    env.msgr->set_sync(true);
    int peer = -1;
    osd_client_t *cl = env.msgr->add_client(&peer, true);
    int snd = 2048;
    assert(setsockopt(cl->peer_fd, SOL_SOCKET, SO_SNDBUF, &snd, sizeof(snd)) == 0);
    char junk[8192];
    memset(junk, 0x5a, sizeof(junk));
    size_t filled = 0;
    while (filled < 16*1024*1024)
    {
        ssize_t n = send(cl->peer_fd, junk, sizeof(junk), MSG_NOSIGNAL);
        if (n < 0)
        {
            assert(errno == EAGAIN || errno == EWOULDBLOCK);
            break;
        }
        assert(n > 0);
        filled += n;
    }
    assert(filled > 0 && filled < 16*1024*1024);
    osd_op_t *a = env.msgr->push_reply(cl, 0xaa);
    std::vector<uint8_t> expect(TEST_BATCH_LEN);
    memcpy(expect.data(), a->reply.buf, OSD_PACKET_SIZE);
    memcpy(expect.data() + OSD_PACKET_SIZE, a->buf, TEST_DATA_LEN);
    env.msgr->send(cl);
    assert(cl->send_list_size == TEST_BATCH_LEN);
    assert(!cl->send_list.empty());
    assert(!cl->write_ready);
    assert(env.write_watched(cl->peer_fd));
    assert(env.ring->sqes.empty());
    std::vector<uint8_t> got(filled);
    read_exact(peer, got.data(), filled);
    for (int i = 0; i < 8 && cl->send_list.size(); i++)
    {
        env.msgr->socket_writable(cl);
        uint8_t tmp[8192];
        while (true)
        {
            ssize_t n = recv(peer, tmp, sizeof(tmp), 0);
            if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK))
                break;
            assert(n > 0);
            got.insert(got.end(), tmp, tmp + n);
        }
    }
    assert(cl->send_list.empty());
    assert(cl->write_ready);
    assert(!env.write_watched(cl->peer_fd));
    assert(got.size() == filled + TEST_BATCH_LEN);
    assert(memcmp(got.data() + filled, expect.data(), TEST_BATCH_LEN) == 0);
    check_released(cl, 1, 0);
    close(peer);
}

int main(int narg, char *args[])
{
    test_zc_tail_before_notify();
    test_zc_notify_before_tail();
    test_zc_other_notify_during_tail();
    test_plain_short_with_zc_notify();
    test_tail_short_again();
    test_tail_eagain();
    test_short_inside_header();
    test_eagain_resend();
    test_eagain_zc_more();
    test_eintr_resend();
    test_eintr_zc_more();
    test_zero_bytes_disconnects();
    test_zero_zc_disconnects();
    test_new_ops_wait_for_tail();
    test_inflight_epollout_ignored();
    test_inflight_tail_epollout_ignored();
    test_sync_eagain_epollout();
    printf("OK\n");
    return 0;
}
