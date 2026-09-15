"""Real loopback HTTP/2 streams and cancellation through managed sockets."""
import asyncio
import unittest
from h2.config import H2Configuration
from h2.connection import H2Connection
from h2.events import RequestReceived, DataReceived, StreamEnded
from core.transport import TransportController, current_transport
from scanners.h2_smuggling import _h2_open, _h2_send_request


class Http2Lab(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.writers = set()
        self.tasks = set()
        self.stall = False
        self.server = await asyncio.start_server(self.handle, "127.0.0.1", 0)
        self.port = self.server.sockets[0].getsockname()[1]
        self.controller = TransportController({"stealth": {"rate_limit_rps": 10000, "per_host_rps": 10000}})
        self.token = current_transport.set(self.controller)

    async def handle(self, reader, writer):
        self.tasks.add(asyncio.current_task())
        self.writers.add(writer)
        conn = H2Connection(config=H2Configuration(client_side=False))
        conn.initiate_connection()
        writer.write(conn.data_to_send())
        await writer.drain()
        try:
            while data := await reader.read(65536):
                for event in conn.receive_data(data):
                    if isinstance(event, RequestReceived) and not self.stall:
                        conn.send_headers(event.stream_id, [(":status", "200")])
                        conn.send_data(event.stream_id, b"local h2 fixture", end_stream=True)
                writer.write(conn.data_to_send())
                await writer.drain()
        except (ConnectionError, asyncio.CancelledError):
            pass
        finally:
            writer.close()
            await writer.wait_closed()
            self.writers.discard(writer)
            self.tasks.discard(asyncio.current_task())

    async def asyncTearDown(self):
        self.controller.cancel()
        current_transport.reset(self.token)
        self.server.close()
        await self.server.wait_closed()
        for writer in list(self.writers):
            writer.close()
        if self.tasks:
            await asyncio.wait_for(asyncio.gather(*list(self.tasks)), 3)

    async def request(self, writer, conn):
        return await _h2_send_request("127.0.0.1", conn, writer,
            [(":method", "GET"), (":scheme", "http"), (":authority", "127.0.0.1"), (":path", "/")])

    async def test_two_actual_streams_and_cleanup(self):
        reader, writer, conn = await _h2_open("127.0.0.1", self.port, False)
        self.assertIsNotNone(conn)
        try:
            expected = {await self.request(writer, conn), await self.request(writer, conn)}
            ended, bodies = set(), {}
            while ended != expected:
                data = await asyncio.wait_for(reader.read(65536), 2)
                self.assertTrue(data)
                for event in conn.receive_data(data):
                    if isinstance(event, DataReceived):
                        bodies[event.stream_id] = event.data
                    if isinstance(event, StreamEnded):
                        ended.add(event.stream_id)
            self.assertEqual(set(bodies.values()), {b"local h2 fixture"})
        finally:
            writer.close()
            await writer.wait_closed()
        self.assertFalse(self.controller.connections)

    async def test_cancel_closes_stalled_connection(self):
        self.stall = True
        reader, writer, conn = await _h2_open("127.0.0.1", self.port, False)
        try:
            await self.request(writer, conn)
            async def read_forever():
                while await reader.read(65536):
                    pass
            pending = asyncio.create_task(read_forever())
            await asyncio.sleep(0.01)
            self.controller.cancel()
            await asyncio.wait_for(pending, 2)
            self.assertFalse(self.controller.connections)
        finally:
            writer.close()
            await writer.wait_closed()
