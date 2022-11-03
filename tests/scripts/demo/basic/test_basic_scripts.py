import os
import uuid

TEST_DIR = os.path.dirname(os.path.abspath(__file__))
KERI_DEMO_SCRIPT_DIR = f'{TEST_DIR}/../../../../scripts/demo'
KERI_SCRIPT_DIR = f'{TEST_DIR}/../../../../scripts'

env = {
    'KERI_DEMO_SCRIPT_DIR': KERI_DEMO_SCRIPT_DIR,
    'KERI_SCRIPT_DIR': KERI_SCRIPT_DIR,
}


def test_demo_script(bash, helpers):
    tempDir = uuid.uuid4().hex
    env['KERI_TEMP_DIR'] = tempDir
    with bash(envvars=env) as s:
        stdout = s.run_script(f'{KERI_DEMO_SCRIPT_DIR}/basic/demo-script.sh')
        assert stdout.endswith("Test Complete")

    helpers.remove_test_dirs(tempDir)


def test_demo_witness_script(bash, helpers):
    tempDir = uuid.uuid4().hex
    env['KERI_TEMP_DIR'] = tempDir
    with bash(envvars=env) as s:
        stdout = s.run_script(f'{KERI_DEMO_SCRIPT_DIR}/basic/demo-witness-script.sh')
        assert stdout.endswith("Test Complete")
        print(stdout)

    helpers.remove_test_dirs(tempDir)


def test_multisig(bash, helpers):
    tempDir = uuid.uuid4().hex
    env['KERI_TEMP_DIR'] = tempDir
    with bash(envvars=env) as s:
        stdout = s.run_script(f'{KERI_DEMO_SCRIPT_DIR}/basic/multisig.sh')
        assert stdout.endswith("Test Complete")
        print(stdout)

    helpers.remove_test_dirs(tempDir)
