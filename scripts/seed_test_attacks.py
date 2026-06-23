#!/usr/bin/env python3
import asyncio
from engine.synthetic import synthetic

asyncio.run(synthetic.inject_all())
