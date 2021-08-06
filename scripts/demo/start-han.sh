#!/bin/bash

kli incept --name han --file tests/app/cli/holder-sample.json
kli query --name han --witness Bgoq68HCmYNUDgOz4Skvlu306o_NY-NrYuKAVhk3Zh9c --prefix EUX0_NKihYcmvuTOSFnLcIf4xhAn0MaAI2FJoCN-gspc
kli wallet start --name han
