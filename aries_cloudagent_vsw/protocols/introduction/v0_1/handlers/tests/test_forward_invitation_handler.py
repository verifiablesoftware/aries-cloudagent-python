from asynctest import TestCase as AsyncTestCase
from asynctest import mock as async_mock

from aries_cloudagent_vsw.config.injection_context import InjectionContext
from aries_cloudagent_vsw.connections.models.connection_record import ConnectionRecord
from aries_cloudagent_vsw.messaging.base_handler import HandlerException
from aries_cloudagent_vsw.messaging.request_context import RequestContext
from aries_cloudagent_vsw.messaging.responder import MockResponder
from aries_cloudagent_vsw.protocols.connections.v1_0.messages.connection_invitation import (
    ConnectionInvitation,
)

from ...messages.forward_invitation import ForwardInvitation

from .. import forward_invitation_handler as test_module

TEST_DID = "55GkHamhTU1ZbTbV2ab9DE"
TEST_VERKEY = "3Dn1SJNPaCXcvvJvSbsFWP2xaCjMom3can8CQNhWrTRx"
TEST_ROUTE_VERKEY = "9WCgWKUaAJj3VWxxtzvvMQN3AoFxoBtBDo9ntwJnVVCC"
TEST_LABEL = "Label"
TEST_ENDPOINT = "http://localhost"
TEST_IMAGE_URL = "http://aries.ca/images/sample.png"


class TestForwardInvitationHandler(AsyncTestCase):
    async def setUp(self):
        self.context = RequestContext(
            base_context=InjectionContext(enforce_typing=False)
        )

        self.context.connection_ready = True
        self.context.message = ForwardInvitation(
            invitation=ConnectionInvitation(
                label=TEST_LABEL,
                did=TEST_DID,
                recipient_keys=[TEST_VERKEY],
                endpoint=TEST_ENDPOINT,
                routing_keys=[TEST_ROUTE_VERKEY],
                image_url=TEST_IMAGE_URL,
            ),
            message="Hello World",
        )
        self.context.update_settings({"accept_invites": False})

    async def test_handle(self):
        handler = test_module.ForwardInvitationHandler()

        responder = MockResponder()
        with async_mock.patch.object(
            test_module, "ConnectionManager", autospec=True
        ) as mock_mgr:
            mock_mgr.return_value.receive_invitation = async_mock.CoroutineMock(
                return_value=ConnectionRecord(connection_id="dummy")
            )

            await handler.handle(self.context, responder)
            assert not (responder.messages)

    async def test_handle_auto_accept(self):
        handler = test_module.ForwardInvitationHandler()
        self.context.update_settings({"accept_invites": True})

        mock_conn_rec = async_mock.MagicMock(connection_id="dummy")
        mock_conn_req = async_mock.MagicMock(label="test")

        responder = MockResponder()
        with async_mock.patch.object(
            test_module, "ConnectionManager", autospec=True
        ) as mock_mgr:
            mock_mgr.return_value.receive_invitation = async_mock.CoroutineMock(
                return_value=mock_conn_rec
            )
            mock_mgr.return_value.create_request = async_mock.CoroutineMock(
                return_value=mock_conn_req
            )

            await handler.handle(self.context, responder)
            assert mock_mgr.return_value.create_request.called_once_with(mock_conn_rec)

            messages = responder.messages
            assert len(messages) == 1
            (result, target) = messages[0]
            assert result == mock_conn_req
            assert target["connection_id"] == "dummy"

    async def test_handle_not_ready(self):
        handler = test_module.ForwardInvitationHandler()
        self.context.connection_ready = False

        with self.assertRaises(HandlerException):
            await handler.handle(self.context, None)
