
    #include <SDL.h>
    #if defined(SDL_VIDEO_DRIVER_X11)
    #include <X11/XKBlib.h>
    #else
    #error No X11 support
    #endif
    int main(void) {return 0;}
    