import "/app/globals.scss";
import Layout from "/components/layout.tsx";
import { Paper, Box, Stack, CssBaseline, Container } from "@mui/material";
import { Twitter, Markunread, GitHub, LinkedIn } from "@mui/icons-material";

const Contact = () => {
  return (
    <Layout> 
        <div className="flex justify-center pt-10 pb-10">
          <div className="pt-14 bg-dr-current_line/40 w-2/5 h-full rounded-lg max-w-4xl">
            <div className="text-5xl text-dr-red font-bold p-10 flex justify-center">
              <h1>Contact Me</h1>
            </div>
            <div className="text-lg text-dr-foreground p-5 pb-16 flex justify-center">
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
    </Layout>
  );
};

export default Contact;
