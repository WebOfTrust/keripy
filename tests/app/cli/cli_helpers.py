# -*- encoding: utf-8 -*-
"""
tests.app.cli.cli_helpers module

"""
import threading
from hio.core.serial import serialing

from hio.base import doing
from hio.help import Deck


class AskDoer(serialing.ConsoleDoer):
    """
    Doer that prompts for input and echoes it back.
    Inherits from ConsoleDoer to handle console open/close.
    """

    def recur(self, tyme, deeds=None):
        """
        Process console input
        """
        # ConsoleDoer.recur calls console.service() which is empty, but we can call it if needed.
        # super(AskDoer, self).recur(tyme) 
        
        line = self.console.get()  # Read from console
        if line:
            msg = f"You said: {line.decode('utf-8')}\n"
            self.console.put(msg.encode('utf-8'))
            return True  # Return True to abort/finish this Doer
        
        return False # Return False to continue

# def test_ask_doer():
#     """
#     Sample test that uses AskDoer (extending ConsoleDoer) to receive and print input.
#     """
#     print("\n\n****************************************************************")
#     print("Please enter some text in the console (or press Enter if testing):")
#     print("****************************************************************\n")
#
#     console = serialing.Console()
#     asker = AskDoer(console=console)
#
#     # Run with a real-time Doist
#     tock = 0.03125
#     doist = doing.Doist(tock=tock, real=True)
#
#     # This will run until AskDoer receives input and returns True
#     doist.do(doers=[asker])
#
#     print("\nTest Complete.")

# def test_ask_doer_mocked():
#     with patch('hio.core.serial.serialing.Console') as MockConsole:
#         mock_console = MockConsole.return_value
#
#         mock_console.get.side_effect = [b'Hello, World!', None]  # Simulate input
#
#         asker = AskDoer(console=mock_console)
#         doist = doing.Doist(tock=0.03125, real=True)
#         doist.do(doers=[asker])
#         print("\nMocked Test Complete.")

class PromptPrinterDoer(doing.Doer):
    """
    Doer that prints lines received from a queue.
    """
    def __init__(self, cmds: Deck, **kwa):
        super(PromptPrinterDoer, self).__init__(**kwa)
        self.cmds = cmds if cmds is not None else Deck()

    def recur(self, tyme, deeds=None):
        """
        Check the queue for input and print it.
        """
        while self.cmds:
            cmd = self.cmds.pop()
            print(f"Received cmd: {cmd}")
        return False  # Continue running


# ------------------------------------------------------------------------------
# Prompt Toolkit Integration Example
# ------------------------------------------------------------------------------

class PromptToolkitDoer(doing.Doer):
    """
    A Doer that runs prompt_toolkit in a separate thread to avoid blocking the hio loop.
    """
    def __init__(self, ins: Deck, cmds: Deck, outs: Deck, **kwa):
        super(PromptToolkitDoer, self).__init__(**kwa)
        self.ins = ins if ins is not None else Deck()
        self.cmds = cmds if cmds is not None else Deck()
        self.outs = outs if outs is not None else Deck()
        self.thread = None
        self.stop_event = threading.Event()
        self.thread_error = None  # To propagate exceptions from thread

    def _prompt_thread(self):
        """
        Thread that runs the blocking prompt_toolkit session.
        """
        try:
            # Import here to avoid hard dependency if not installed
            from prompt_toolkit import PromptSession
            session = PromptSession()

            print("\nkREPL started. Ctrl-D or 'exit' to quit")
            
            while not self.stop_event.is_set():
                try:
                    # blocks here, but it's okay because we are in a thread
                    text = session.prompt('> ')
                    self.ins.push(text)
                    if text.strip().lower() == 'exit':
                        break
                except (EOFError, KeyboardInterrupt):
                    self.ins.push('exit')
                    break
        except Exception as ex:
            self.thread_error = ex

    def enter(self, **kwa):
        """
        Start the input thread on enter
        """
        self.thread = threading.Thread(target=self._prompt_thread, daemon=True)
        self.thread.start()

    def recur(self, tyme, deeds=None):
        """
        Check the queue for input from the thread.
        """
        # Check for thread errors first to propagate them immediately
        if self.thread_error:
            raise self.thread_error

        while self.ins:
            cmd = self.ins.pop()
            if cmd == 'exit':
                self.stop_event.set()
                return True  # Stop the Doer
            print(f"Processing command: {cmd}")
            self.cmds.push(cmd)
                
        return False

    def exit(self):
        """
        Cleanup
        """
        self.stop_event.set()
        print("PromptToolkitDoer exiting...")
        # We can't easily kill the blocking prompt in the thread, but setting the event
        # prevents the loop from restarting if it wakes up.

def test_prompt_toolkit_integration():
    """
    Demonstrates using prompt_toolkit with hio
    """
    try:
        import prompt_toolkit
    except ImportError:
        print("Skipping test_prompt_toolkit_integration: prompt_toolkit not installed")
        return

    print("\n\n****************************************************************")
    print("kREPL - KERI Read-Eval-Print Loop using prompt_toolkit")
    print("Includes history (Up/Down), and Ctrl-R search!")
    print("****************************************************************\n")

    ins = Deck()
    cmds = Deck()
    outs = Deck()
    printer = PromptPrinterDoer(cmds=outs)
    prompter = PromptToolkitDoer(ins, cmds, outs)
    doist = doing.Doist(tock=0.1, real=True)
    doist.do(doers=[prompter, printer])
    print("\nPrompt Toolkit Test Complete.")



if __name__ == "__main__":
    # test_ask_doer_mocked()
    # test_ask_doer() # Requires real console, commented out for auto-runs
    test_prompt_toolkit_integration() # Uncomment to test if prompt_toolkit is installed
