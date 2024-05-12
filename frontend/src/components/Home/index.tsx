import "/src/index.scss";
import {
  Apple,
  Code,
  EmojiFlags,
  VpnKey,
  Surfing,
  CellTower,
} from "@mui/icons-material";
//import { Paper, Box, Stack, CssBaseline, Container } from "@mui/material";

const Home = () => {
  return (
    <div className="flex justify-center pt-10 pb-10">
      <div className="pt-14 bg-dr-current_line/40 w-3/5 max-w-4xl h-full rounded-lg">
        <div className="text-5xl text-dr-red font-bold p-10 flex justify-center">
          <h1>About Me</h1>
        </div>
        <div className="text-lg text-dr-foreground p-5 px-28 flex justify-center">
          Hi my name is Alex. I'm a security researcher and ctf player. My work,
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
              Trying to get good at crypto ?? (but failing) <VpnKey />
            </li>
            <li>Messing around with linux</li>
          </ul>
        </div>
      </div>
    </div>
  );
};

export default Home;
