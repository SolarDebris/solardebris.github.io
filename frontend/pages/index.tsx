import "/app/globals.scss";
import {
  Apple,
  Code,
  EmojiFlags,
  VpnKey,
  Surfing,
  CellTower,
  //AdbIcon, 
  //AirplayIcon,
  //AndriodIcon,
  //BluetoothOutlinedIcon,
  //CatchingPokemonOutlinedIcon,
  //CoffeeOutlinedIcon,
  //LteMobiledataOutlinedIcon,
  //GamesOutlinedIcon,
  //HeadphonesOutlinedIcon,

} from "@mui/icons-material";
import Layout from "../components/layout.tsx";
import localFont from "next/font/local";


const spaceGrotesk = localFont({
    src: '../public/fonts/SpaceGrotesk-Regular.ttf',
    display: 'swap',
})

const Home = () => {
  return (

    <Layout>
    <div className="flex justify-center pt-10 pb-10">
      <div className="pt-14 bg-dr-current_line/40 w-3/5 max-w-4xl h-full rounded-lg">
        <div className="text-5xl text-dr-red font-bold p-10 flex justify-center">
          <h1 className={spaceGrotesk.className}>About Me</h1>
        </div>
        <div className="text-lg text-dr-foreground p-5 px-28 flex justify-center">
          Hi my name is Alex. I&apos;m a security researcher and ctf player. My work,
          projects, and interests include:
        </div>
        <div className="text-lg text-dr-foreground p-5 px-36 pb-16 flex justify-center">
          <ul className="list-disc">
            <li>
                PWN and RE <EmojiFlags />
            </li>
            <li>
                Binary Ninja <Code />
            </li>
            <li>
                VR on Low Level Network Stacks
            </li>
            <li>
                *OS Vulnerability Research <Apple />
            </li>
            <li>
                A little bit of baseband vr <CellTower />
            </li>
            <li>
                Surfing <Surfing />
            </li>
            <li>Chess</li>
            <li>
              Trying to get good at crypto ?? (but failing) <VpnKey />
            </li>
            <li>Messing around with linux environment and dotfiles</li>
          </ul>
        </div>
      </div>
    </div>
    </Layout>
  );
};

export default Home;
