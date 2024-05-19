import "/app/globals.scss";
import * as React from "react";
import { Paper, Chip, Stack, CssBaseline, Container } from "@mui/material";
import { ThemeProvider, createTheme } from "@mui/system";
import DOMPurify from "dompurify";
import localFont from "next/font/local";

interface Tag {
    name: string
}

const spaceGrotesk = localFont({
     src: '../public/fonts/SpaceGrotesk-Regular.ttf',
     display: 'swap',
})


const Tag: React.FC<Tag> = (props) => {

  console.log("Tag Inside Component");
  console.log(props.name);

  return (

    <div className="px-2 opacity-85">

        <Chip 
            className={spaceGrotesk.className}
            sx={{
                bgcolor: "#6272a4",
                color: "#8be9fd",
                bgopacity: 0.5,
                boxShadow: 3,
                "& > :not(style)": {

                },
            }}        

            label={props.name} />
    </div>
  );
};

export default Tag;
