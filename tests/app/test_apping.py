# -*- encoding: utf-8 -*-
"""
tests.app.apping module

"""


from keri.app import Consoler


class FakeConsole:
    """Deterministic fake console for testing Consoler without a real terminal.

    Attributes:
        opened (bool): True when the console is open.
        inputs (list): Queue of bytearray lines to return from get().
        outputs (list): All bytes written via put().
    """

    def __init__(self, inputs=None):
        self.opened = False
        self.inputs = list(inputs) if inputs else []
        self.outputs = []

    def reopen(self):
        self.opened = True
        return True

    def get(self):
        if not self.inputs:
            return bytearray()
        return self.inputs.pop(0)

    def put(self, data=b'\n'):
        self.outputs.append(data)

    def close(self):
        self.opened = False


def test_app():
    """
    """
    """End Test"""


def test_consoler():
    """Test Consoler with deterministic fake console."""

    # 1. enter() opens the console
    fake = FakeConsole()
    doer = Consoler(console=fake)
    doer.enter()
    assert fake.opened is True

    # 2. no input returns False and produces no output
    assert doer.recur(0.0) is False
    assert fake.outputs == []

    # 3. truly empty input (Enter on blank line) — no output
    fake.inputs.append(bytearray(b''))
    assert doer.recur(0.0) is False
    assert fake.outputs == []

    # 4. whitespace-only input produces bytes guidance
    fake.inputs.append(bytearray(b'  '))
    assert doer.recur(0.0) is False
    assert fake.outputs == [b"Try one of: l[eft] r[ight] w[alk] s[top]\n"]

    # 5. right produces the expected bytes output
    fake.outputs.clear()
    fake.inputs.append(bytearray(b'right'))
    assert doer.recur(0.0) is False
    assert fake.outputs == [b"Did: turn right\n"]

    # 6. left produces the expected bytes output
    fake.outputs.clear()
    fake.inputs.append(bytearray(b'left'))
    assert doer.recur(0.0) is False
    assert fake.outputs == [b"Did: turn left\n"]

    # 7. walk produces the expected bytes output
    fake.outputs.clear()
    fake.inputs.append(bytearray(b'walk'))
    assert doer.recur(0.0) is False
    assert fake.outputs == [b"Did: walk 1\n"]

    # 8. stop produces the expected bytes output
    fake.outputs.clear()
    fake.inputs.append(bytearray(b'stop'))
    assert doer.recur(0.0) is False
    assert fake.outputs == [b"Did: stop \n"]

    # 9. invalid input produces both expected messages
    fake.outputs.clear()
    fake.inputs.append(bytearray(b'jump'))
    assert doer.recur(0.0) is False
    assert len(fake.outputs) == 2
    assert fake.outputs[0] == b"Invalid command: jump\n"
    assert fake.outputs[1] == b"Try one of: l[eft] r[ight] w[alk] s[top]\n"

    # 10. every captured output is bytes
    for out in fake.outputs:
        assert isinstance(out, (bytes, bytearray))

    # 11. recur() continues to return False
    fake.outputs.clear()
    fake.inputs.append(bytearray(b'right'))
    for _ in range(5):
        assert doer.recur(0.0) is False
    assert len(fake.outputs) == 1

    # 12. exit() closes the console
    doer.exit()
    assert fake.opened is False


if __name__ == "__main__":
    test_consoler()
