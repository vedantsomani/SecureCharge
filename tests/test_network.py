import asyncio
from securecharge.network import loopback
from securecharge.keys import Keyring
from securecharge.messages import example_start
from securecharge import security
import copy
import pytest


def test_actual_websocket_flow_and_retry():
    r = asyncio.run(loopback())
    assert r["start_response"][0] == 3 and r["stop_response"][0] == 3
    assert r["stop_response"] == r["retry_response"]
    assert r["ledger_rows"] == 1 and r["billed_paise"] == 15000
    assert r["tamper_response"][0] == 4 and r["tamper_response"][3] == "BAD_TAG"


def test_reply_is_authenticated_and_bound_to_request():
    k = Keyring.generate()
    request = security.attach(example_start(), k, ts=100)
    frame = [3, request.unique_id, {"transactionId": 1, "idTagInfo": {"status": "Accepted"}}]
    reply = security.sign_reply(frame, request, k, 100)
    assert security.verify_reply(reply, request, k, 100) == frame
    bad = copy.deepcopy(reply)
    bad["ocpp"][2]["transactionId"] = 999
    with pytest.raises(security.BadTag):
        security.verify_reply(bad, request, k, 100)
    second = security.attach(example_start(), k, ts=100)
    with pytest.raises(security.BadTag):
        security.verify_reply(reply, second, k, 100)
