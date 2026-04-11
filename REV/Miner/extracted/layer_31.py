import sys
import signal


ASCII_ART = r"""
############################################################################
############################################################################
                                 .##@@@@#***#@#-:....-.:-:=..-::.-.:.=::=-:+
     You :(                        . =*%@####@@-=...::....       :-+-=--:-::
         \           .+:.            :***####@@@+:    ..::  ..::- :::  -::-:
          \             :@-:           ***#####@@@  ..:.:-:.:..:::.::  :--=+
           \               @+*             #*#%@@@@::..::::::::=-::::=-:-::*
             :+**:     :#@.@@.             =**#%@@:                .-+  ::+*
           =.%#@@@@@@@ +   .@@              @%@@@:      -:.: ::::.-::::+=:*=
          = =#%@@@@@@# *  : #@              @@@@@       -:::::..:::.-::==:=*
          - +#+*+%@@% *:    -.               @@@# ::.:...:..  ::::-:-:::==+*
          +%#@:::.#= +-    =-                +@@:  ::........::::::      .:-
     *:@*@  -:@@.-@*@#:    %.                 #@   -:..::.. ..:-=.:-:-:-=+--
   -@@@=#-    *#=@@=@ =@@@::                  =%           .-:::-:::---=--++
  ##   *+=:.: .   @## -@@@=:-                 +%   :......:=::=+:  *-=+-=-=-
          ***.*  -=@  -@@@#:=                 #% =-.....::.:-::::=-::#=++:-=
            .-    +# *+:@@@%:                 %*  .=::::.::::...:::::-=-=+==
                  -@  :=+*#                   %+    :+::::.:-.-:::=--=--+*=+
                  -+@  =-+*                   @: ╻ ╻┏━┓╻ ╻┏━┓  ┏━╸╻  ┏━┓┏━╸ 
                   = -+-@                     =| ┗┳┛┃ ┃┃ ┃┣┳┛  ┣╸ ┃  ┣━┫┃╺┓ 
                   +--@=*                    ||=  ╹ ┗━┛┗━┛╹┗╸  ╹  ┗━╸╹ ╹┗━┛ 
                   =+@++ =*+                  @@  +--:.:.+-:==:::--:+++=++*+
                  +#@:*@@@=@-               #@@   -::-:=:.+-:--:::--=:+++**=
                *@%@@  @@@                *@%@*.   ..:::.::+:-===::=-=*==%**
               *@@       ##%+:-==        @@@%@:.-.:.::-:::-::++--+:*-++**+**
              #@#            %@@@       #@#@@+- --:::-::::=----:=+*#=++=++*+
       %@##%*@@%               @@     *#@##%**+::-==--:::==:-=-=-*+=++#*+***
            %@@.              @@*   -*%@@%@#***=-:. --=:==::===-+*+*#####@@@
############################################################################
############################################################################"""

MOD = 10**9 + 7 
INITIAL_VALUES = [1337, 2137, 999]
NUMBER_OF_MINERALS = 13

FLAG1_DATA = [
    (13691526, 85),
    (67714635, 250),
    (45889193, 92),
    (119333921, 92),
    (28660401, 71),
    (91192320, 226),
    (98698869, 14),
]


FLAG2_DATA = [
    (19385771243582136162726, 119),
    (20338468563599170406034, 244),
    (20348006767133331653585, 84),
    (20855346972076738813432, 108),
    (21275032782538569035493, 44),
    (21688316937478910332906, 213),
    (10000000000000000000000, 248),
    (10434543483380626658076, 213),
    (11432360796540021360875, 89),
    (11893508966092798746611, 0),
    (12629823227009614311307, 71),
    (13239336466487376418254, 130),
    (14213837926783723743645, 144),
    (15144837827511220276057, 129),
    (15901977772834060831411, 234),
    (16759029998774462742839, 143),
    (17454032695551734274782, 170),
    (18154830948193389431256, 102),
    (18647374405210769869223, 151),
]

def sss(ts):
    c_x, c_y, c_z = INITIAL_VALUES
    s_r = range(ts) if sys.version_info[0] >= 3 else xrange(ts)

    for s in s_r:
        n_x = (3 * c_x + 2 * c_y + 5 * c_z) % MOD
        n_y = (1 * c_x + 4 * c_y + 0 * c_z) % MOD
        n_z = (0 * c_x + 1 * c_y + 2 * c_z) % MOD

        c_x, c_y, c_z = n_x, n_y, n_z

        if s % 10_000_000 == 0 and s > 0:
            sys.stdout.write(f"\rSimulation progress for current character: {s / ts * 100:.20f}%")
            sys.stdout.flush()


    print("\nBlock added to blockchain!")
    return c_x

def decode_flag(flag_data, new_pickaxe=False):
    mined_chars = []

    for i, (ts, ev) in enumerate(flag_data):
        print(f"[{i+1}/26] Calculating key...")

        ksx = sss(ts)
        kb = ksx & 0xFF

        mined_chars.append(chr(ev ^ kb))

        print(f"{mined_chars[-1]}")
        print("-" * 40)

    if new_pickaxe and mined_chars:
        mined_chars = mined_chars[-NUMBER_OF_MINERALS:] + mined_chars[:-NUMBER_OF_MINERALS]

    return ''.join(mined_chars)


def main():
    f1=decode_flag(FLAG1_DATA, new_pickaxe=False)
    f2=decode_flag(FLAG2_DATA, new_pickaxe=True)
    f8 = f1
    diamond = ''
    f9 = 'No flag for you :('
    g = 'putCTFc'
    if f1.startswith('DIAMOD{') and f1.endswith('}'):
        print("Flag1 looks correct, checking Flag2...")
        f1 = f2 + f1
        print("You are correct there is a diamond here!")
        if isinstance(f2, tuple):
            f2 = f2[0]
            f1 = 'NULL' + f1
            final_flag = []
            f4 = 0
            for c in f2:
                f5 = (ord(c) ^ 0x11) + 3
                f6 = f5 ^ 0x2A
                final_flag.append(chr(f6))
                final_flag.append(f4)
                final_flag.append(g)
        else:
            f3 = 'No flag for you :('
            if f2 != f3:
                print(f"\n\nUnexpected flag2 value: {f2}\n")
                f1 = f6
                g = 'FTCctup'
            else:
                print("Lets find diamond :D\n")
                print(f"\n\nFlag2 is correct, but flag1 is not. Check your calculations for flag1.\n")
                diamond = ''.join(
                    map(
                        lambda x: chr(
                            ((x ^ 0x2A) - 3) ^ 0x11
                        ),
                        [
                            (((ord(c) ^ 0x11) + 3) ^ 0x2A)
                            for c in ''.join(
                                chr(int(x, 16))
                                for x in [
                                "44","49","41","4d","4f","4e","44","7b","59","30","55","5f","46","30","55",
                                "4e","44","5f","34","5f","44","31","34","4d","30","4e","44","5f","31","4e",
                                "5f","34","5f","4d","31","4e","33","52","34","4c","5f","4d","31","4e","33",
                                "21","7d"
                                ]
                            )
                        ]
                    )
                )
                print(f"\n\n{diamond} or flag??\n")
                diamond = f2
                print(f"\n\nSuccess! Full flag: FLAG{diamond}\n")
    elif (
        (lambda x: all([
            x[::][0:5] == ''.join(chr(c) for c in [70,76,65,71,123]),
            ''.join(map(chr,[116,101,115,116,105,110,103])) in x,
            x[-1:] == chr(125)
        ]))
    )(f1):
        f1 = (lambda *_: f4)()
        print(f"\n\nSuccess! Full flag(f2 is a trap): {f1}\n")
  
    elif (lambda s: all(a==b for a,b in zip(s, bytes([112,117,116,99,67,84,70]).decode())))(f1):
        (__import__('builtins').__dict__['print'])(
            "\n\nSuccess! Full flag: {}\n".format(''.join((f1,f2)))
        ) 
    else:
        f12 = ''.join(
            chr(((x ^ 0x33) - 7) ^ 0x12)
            for x in [
                (((ord(c) ^ 0x12) + 7) ^ 0x33)
                for c in ''.join(
                    chr(int(h, 16)) for h in [
                        "43","54","46","7b","64","6f","6e","74","5f","6c","6f","6f",
                        "6b","5f","66","6f","72","5f","64","69","61","6d","6f","67","73","7d"
                    ]
                )
            ]
        )

        print("\n\nSuccess! Full flag:", f12, "\n")

if __name__ == "__main__":
    sys.setrecursionlimit(2000)
    try:
        main()
    except KeyboardInterrupt:
        signal.signal(signal.SIGINT, signal.SIG_IGN)
        
        print("\n\nEvery gambler gives up before their biggest win :(\n")
        print(ASCII_ART)    
    
