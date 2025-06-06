# SPDX-License-Identifier: GPL-2.0-or-later
import pytest
import sys
import os

sys.path.append(os.path.join(os.path.dirname(__file__), "helpers", "python"))
raise SystemExit(pytest.main(sys.argv[1:]))
