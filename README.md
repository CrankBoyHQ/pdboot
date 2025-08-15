# PDBoot

A simple boot shim that merely launches another playdate application. This can be used as part of, for example, a self-updater.

## Limitations

- Only works with Pure-C playdate games. Cannot load Lua games.
- The launched playdate application must be specially compiled, and built separately for rev A and rev B devices.
- Heap size must be specified in advance. This forces a limit on the size of the program to be loaded.

## How to use:

First, build pdboot:

```bash
make -j 4
```

(Note: replace MyGame.pdx with your actual pdx)

```bash
# create .pdb for rev A:
python3.11 elfboiler/elfboiler.py Source/pdex.elf MyGame.pdx/appA.pdb 0x60000000

# create .pdb for rev B:
python3.11 elfboiler/elfboiler.py Source/pdex.elf MyGame.pdx/appB.pdb 0x90000000

# replace .bin with pdboot:
cp path/to/pdboot/PDBoot.pdx/pdex.bin MyGame.pdx/pdex.bin
```

If you then run `MyGame.pdx` on a playdate device, it should launch via pdboot. You can check the output log in the simulator to confirm; pdboot should print some messages.

## Troubleshooting

If `elfboiler.py` is failing, most likely you are using a type of relocation symbol that hasn't been implemented yet. You can try implementing it based on the documentation linked in the output of `elfboiler.py`, or you can change compile settings. Try using gcc, and don't use `-fPIC` (position-independent code).

## Extra features:

If you include `pdboot.h`, you can access some data about pdboot, which is stored at the address returned by `playdate->graphics->getFrame()`. If the `magic` field matches the string in the header, then that means the game has been launched by pdboot. Otherwise, pdboot was not involved in launching the game.