# FUEGO ELITE
Fuego Elite is a kernel module for Microsoft Windows XP that provides the ability to draw boxes around any player in Counter-Strike 1.6.

To achieve that it patches the System Service Descriptor Table (SSDT) and hooks NtGdiExtEscape, which is called during redraw in Counter-Strike, to access memory and draw the boxes using NtGdiSetPixel. Offsets for the player information are retrieved dynamically using pattern matching.

Please note that this software is only a Proof of Concept (POC). You will need the HLSDK to compile.

BY DOWNLOADING THIS SOURCE CODE YOU AGREE NOT TO USE IT IN ANY MANNER WHICH IS UNLAWFUL, ILLEGAL, FRAUDULENT OR HARMFUL, OR IN CONNECTION WITH ANY UNLAWFUL, ILLEGAL, FRAUDULENT OR HARMFUL PURPOSE OR ACTIVITY INCLUDING BUT NOT LIMITED TO FRAUD, IDENTITY THEFT, OR UNAUTHORIZED COMPUTER SYSTEM ACCESS. THIS SOURCE CODE IS ONLY MADE AVAILABLE FOR ACADEMIC AND RESEARCH PURPOSES.
