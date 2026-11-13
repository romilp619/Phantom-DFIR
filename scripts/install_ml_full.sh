#!/usr/bin/env bash
# Install transformers + peft with all dependencies. Accept the download; it's worth it.
set -eu
VENV="$HOME/phantom-eval-venv"
"$VENV/bin/pip" install transformers peft -q 2>&1 | tail -5
"$VENV/bin/python" -c "import transformers; print('transformers', transformers.__version__); import peft; print('peft', peft.__version__); import torch; print('torch', torch.__version__, 'cuda', torch.cuda.is_available())" 2>&1