import "/src/index.scss";
import Navbar from "../Navbar";
import {
  Apple,
  Code,
  Coffee,
  EmojiFlags,
  VpnKey,
  Surfing,
  Headphones,
  CellTower,
  VideogameAsset,
} from "@mui/icons-material";
import { Paper, Box, Stack, CssBaseline, Container } from "@mui/material";

//GitHub, Gamepad, Headphones, Twitter LinkedIn, LTEMobiledata Markunread

const Home = () => {
  return (
    <div class="flex justify-center pt-10 pb-10">
      <div class="pt-14 bg-dr-current_line/40 w-3/5 h-full rounded-lg">
        <div class="text-5xl text-dr-red font-bold p-10 flex justify-center">
          <h1>About Me</h1>
        </div>
        <div class="text-lg text-dr-foreground p-5 px-28 flex justify-center">
          Hi my name is Alex. I'm a security researcher and ctf player in melby.
          My work, projects, and interests include:
        </div>
        <div class="text-lg text-dr-foreground p-5 px-36 pb-16 flex justify-center">
          <ul class="list-disc">
            <li>
              PWN and RE <EmojiFlags />
            </li>
            <li>Binary Ninja</li>
            <li>
              Operating Systems Internals <Code />
            </li>
            <li>
              A little bit of *OS Vulnerability Research <Apple />
            </li>
            <li>
              A little bit of baseband vr <CellTower />
            </li>
            <li>
              Surfing <Surfing />
            </li>
            <li>Chess</li>
            <li>
              Trying to get good at cryto ?? (but failing) <VpnKey />
            </li>
          </ul>
        </div>
      </div>
    </div>
  );
};

export default Home;
