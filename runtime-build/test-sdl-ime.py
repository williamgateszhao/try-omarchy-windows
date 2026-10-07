#!/usr/bin/env python3
"""Headless regression for the actual policy, with modeled SDL/Win32 calls."""
import argparse
import os
from pathlib import Path
import subprocess
import tempfile


def function(source, signature):
    start = source.index(signature + '\n{')
    opening = source.index('{', start)
    depth = 1
    end = opening + 1
    while depth:
        depth += (source[end] == '{') - (source[end] == '}')
        end += 1
    return source[start:end]


def policy(source):
    return '\n'.join(function(source, signature) for signature in [
        'static struct sdl2_console *get_scon_from_window(uint32_t window_id)',
        'static void sdl2_win32_disable_ime(struct sdl2_console *scon)',
        'static int sdl2_win32_text_input(void *opaque, SDL_Event *event)',
    ])


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('source', type=Path)
    args = parser.parse_args()
    source = (args.source / 'ui/sdl2.c').read_text(encoding='utf-8')
    init_start = source.index('#ifdef _WIN32\n    /* SDL2 enables text input')
    init = source[init_start:source.index('#endif', init_start) + len('#endif')]
    cleanup = function(source, 'static void sdl_cleanup(void)')
    assert cleanup.index('SDL_DelEventWatch') < cleanup.index('SDL_QuitSubSystem')
    create = function(source, 'void sdl2_window_create(struct sdl2_console *scon)')
    fixture = r'''
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#ifndef _WIN32
#define _WIN32 1
#endif
#define SDL_WINDOWEVENT 1
#define SDL_WINDOWEVENT_FOCUS_GAINED 2
#define SDL_WINDOWEVENT_FOCUS_LOST 3
#define SDL_WINDOW_FULLSCREEN_DESKTOP 1
#define SDL_WINDOW_RESIZABLE 2
#define SDL_WINDOW_HIDDEN 4
#define SDL_WINDOW_OPENGL 8
#define SDL_WINDOWPOS_UNDEFINED 0
#define DISPLAY_GL_MODE_ES 1
#define SDL_HINT_RENDER_DRIVER "driver"
#define SDL_HINT_RENDER_BATCHING "batching"
#define SDL_GL_SHARE_WITH_CURRENT_CONTEXT 1
#define SDL_VERSION(v) (*(v) = 2)
typedef struct { uint32_t id; bool context, shown, alive; } SDL_Window;
typedef struct { int type; struct { uint32_t windowID; int event; } window; } SDL_Event;
typedef struct { int version; struct { struct { SDL_Window *window; } win; } info; } SDL_SysWMinfo;
typedef int (*Watch)(void *, SDL_Event *);
struct options { int gl; };
struct sdl2_console {
    void *surface;
    bool hidden, opengl;
    SDL_Window *real_window;
    int winctx, real_renderer;
    struct options *opts;
    struct { bool con; } dcl;
};
static struct sdl2_console consoles[3];
static struct sdl2_console *sdl2_console = consoles;
static int sdl2_num_outputs = 3, gui_fullscreen;
static SDL_Window windows[20], *focus_window, *ime_main;
static int next_id, native_starts, native_stops;
static bool text_active = true;
static Watch watch;
static bool qemu_console_is_graphic(bool con) { return con; }
static SDL_Window *SDL_GetKeyboardFocus(void) { return focus_window; }
static SDL_Window *SDL_GetWindowFromID(uint32_t id) {
    return id && id <= next_id && windows[id].alive ? &windows[id] : NULL;
}
static int SDL_GetWindowWMInfo(SDL_Window *w, SDL_SysWMinfo *i) {
    assert(w && w->alive && i->version == 2);
    i->info.win.window = w; return 1;
}
static void ImmAssociateContext(SDL_Window *w, void *context) {
    assert(w && w->alive && !context); w->context = false;
}
/* SDL 2.32.10's native IME backend operates on its first IME window.
 * A global text flag or StopTextInput alone cannot clear every window.
 */
static void native_start(void) {
    if (!focus_window) return;
    if (!ime_main) ime_main = focus_window;
    if (ime_main->alive) ime_main->context = true;
    native_starts++;
}
static void native_stop(void) {
    if (ime_main && ime_main->alive) ime_main->context = false;
    native_stops++;
}
static int SDL_IsTextInputActive(void) { return text_active; }
static void SDL_StopTextInput(void) { native_stop(); text_active = false; }
static void SDL_StartTextInput(void) { text_active = true; native_start(); }
static void SDL_AddEventWatch(Watch w, void *opaque) { assert(!opaque); watch = w; }
static void acquire_focus(SDL_Window *w) {
    assert(w && w->alive && w->shown);
    if (text_active) native_stop();
    focus_window = w;
    SDL_Event event = {.type = SDL_WINDOWEVENT,
                      .window = {.windowID = w->id, .event = SDL_WINDOWEVENT_FOCUS_GAINED}};
    assert(watch && watch(NULL, &event) == 1);
    /* Match SDL_SetKeyboardFocus: the native start happens AFTER the watch.
     * Checking only at the later SDL_PollEvent stage is too late for keys.
     */
    if (text_active) native_start();
}
static int surface_width(void *s) { return 800; }
static int surface_height(void *s) { return 600; }
static SDL_Window *SDL_CreateWindow(const char *s, int x, int y, int w, int h, int flags) {
    SDL_Window *window = &windows[++next_id];
    *window = (SDL_Window){.id = next_id, .context = true, .alive = true};
    if (!(flags & SDL_WINDOW_HIDDEN)) {
        window->shown = true;
        acquire_focus(window); /* before QEMU receives the returned pointer */
    }
    return window;
}
static void SDL_ShowWindow(SDL_Window *w) {
    if (!w->shown) { w->shown = true; acquire_focus(w); }
}
static void SDL_SetHint(const char *s, const char *v) {}
static int SDL_GL_MakeCurrent(SDL_Window *w, int c) { return 0; }
static int SDL_GL_SetAttribute(int a, int b) { return 0; }
static int SDL_GL_CreateContext(SDL_Window *w) { return 1; }
static void SDL_GL_SetSwapInterval(int interval) {}
static int SDL_CreateRenderer(SDL_Window *w, int i, int flags) { return 1; }
static void win_pinch_create(struct sdl2_console *s) {}
static void sdl_update_caption(struct sdl2_console *s) {}
''' + policy(source) + '\n' + create + r'''
static void initialize(void) {
''' + init + r'''
}
int main(void) {
    struct options opts = {0};
    for (int i = 0; i < 3; ++i) {
        consoles[i].opts = &opts;
        consoles[i].surface = (void *)1;
        consoles[i].dcl.con = i != 2; /* two guests and a QEMU text console */
    }
    initialize();
    assert(!text_active && watch && !ime_main);
    sdl2_window_create(&consoles[0]);
    assert(!text_active && !consoles[0].real_window->context);
    sdl2_window_create(&consoles[1]);
    assert(!text_active && !consoles[1].real_window->context);
    for (int i = 0; i < 6; ++i) {
        acquire_focus(consoles[i % 2].real_window);
        assert(!text_active && !focus_window->context);
    }
    sdl2_window_create(&consoles[2]);
    assert(text_active && consoles[2].real_window->context && native_starts);
    for (int i = 0; i < 6; ++i) {
        acquire_focus(consoles[i % 2].real_window);
        assert(!text_active && !focus_window->context);
        acquire_focus(consoles[2].real_window);
        assert(text_active && focus_window->context);
    }
    /* Recreating a hidden output must not disable the focused monitor. */
    SDL_Window *old = consoles[1].real_window;
    old->alive = false;
    consoles[1].real_window = NULL;
    consoles[1].hidden = true;
    sdl2_window_create(&consoles[1]);
    assert(!consoles[1].real_window->context && !consoles[1].real_window->shown);
    assert(text_active && focus_window == consoles[2].real_window);
    SDL_ShowWindow(consoles[1].real_window);
    assert(!text_active && !focus_window->context);
    /* A visible replacement must switch away from the monitor's text mode. */
    acquire_focus(consoles[2].real_window);
    consoles[0].real_window->alive = false;
    consoles[0].real_window = NULL;
    sdl2_window_create(&consoles[0]);
    assert(focus_window == consoles[0].real_window);
    assert(!text_active && !focus_window->context);
    /* Ignore stale, out-of-order, and non-focus events. */
    SDL_Event event = {.type = SDL_WINDOWEVENT,
                      .window = {.windowID = old->id, .event = SDL_WINDOWEVENT_FOCUS_GAINED}};
    watch(NULL, &event); assert(!text_active);
    event.window.windowID = consoles[2].real_window->id;
    watch(NULL, &event); assert(!text_active);
    event.window.event = SDL_WINDOWEVENT_FOCUS_LOST;
    watch(NULL, &event); assert(!text_active);
    event.type = 999;
    watch(NULL, &event); assert(!text_active);
    assert(native_stops > 0);
    return 0;
}
'''
    with tempfile.TemporaryDirectory(prefix='sdl-ime-') as directory:
        root = Path(directory)
        (root / 'test.c').write_text(fixture, encoding='utf-8')
        subprocess.run([os.environ.get('CC', 'gcc'), '-std=gnu11', '-O2',
                        str(root / 'test.c'), '-o', str(root / 'test.exe')], check=True)
        subprocess.run([str(root / 'test.exe')], check=True)
    print('ok - SDL IME focus ordering, per-window contexts, text consoles, hidden/recreated outputs and stale events')


if __name__ == '__main__':
    main()
