# mcapi
Moon CLang interface (mcapi)

## Table of Contents

- [Installation](#installation)
- [Usage](#usage)

## Installation

**Install the MCAPI using git**:

```bash
git clone https://github.com/reslaid/mcapi.git
```

## Usage

### Initializing MCAPI

```python
import os
from mcapi.dllapi import CEncoding, CTypes, DLLAPI

# Initialization
dll: DLLAPI = DLLAPI(
    library='msvcrt' if os.name == 'nt' else 'c',
    local=False,
    base_logger=None # accepted logging.Logger / None
)

dll.call('printf', 'Hello World!'.encode())
```
