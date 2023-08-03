import "/src/index.scss";
import Navbar from "../Navbar";
import { Paper, Box, Stack, CssBaseline, Container } from "@mui/material";
import { Twitter, Markunread, GitHub, LinkedIn } from "@mui/icons-material";

const Contact = () => {
  return (
    <div class="flex justify-center pt-10 pb-10">
      <div class="pt-14 bg-dr-current_line/40 w-2/5 h-full rounded-lg max-w-7xl">
        <div class="text-5xl text-dr-red font-bold p-10 flex justify-center">
          <h1>Contact Me</h1>
        </div>
        <div class="text-lg text-dr-foreground p-5 pb-16 flex justify-center">
          <ul>
            <li>
              <Markunread />: alexanderschmith@protonmail.com
            </li>
            <li>
              <GitHub />:{" "}
              <a href="https://github.com/SolarDebris">SolarDebris</a>
            </li>
            <li>
              <Twitter />: @solardebris
            </li>
            <li>Discord: solardebris</li>
          </ul>
        </div>
      </div>
    </div>
  );
};

export default Contact;
