//'use client'

import * as React from "react";
//import { Link, NavLink } from "react-router-dom";
import Link from 'next/link'
import localFont from 'next/font/local';
import {
  Avatar,
  AppBar,
  IconButton,
  Typography,
  Toolbar,
  Stack,
  Button,
} from "@mui/material";
import "/app/globals.scss";


const spaceGrotesk = localFont({
    src: '../public/fonts/SpaceGrotesk-Regular.ttf',
    display: 'swap',
})


const Navbar = () => {
  const [anchorEl, setAnchorEl] = React.useState(null);
  const open = Boolean(anchorEl);
  const handleClick = (event) => {
    setAnchorEl(event.currentTarget);
  };
  const handleClose = () => {
    setAnchorEl(null);
  };

  console.log(spaceGrotesk.className);

  return (
    <div className="bg-dr-current_line text-dr-cyan w-full flex justify-center h-16">
        <div className="flex max-w-4xl justify-center">
            <div className="flex items-center px-6 pr-48">
                <IconButton
                    size="medium"
                    edge="start"
                    color="inherit"
                    aria-label="logo"
                >
                    <a href="https://github.com/SolarDebris">
                        <Avatar alt="SolarDebris" src="/public/logo.jpg" />
                    </a>
                </IconButton>
                <p className={spaceGrotesk.className}>Alex Schmith</p>
            </div>
            <div className="flex items-center px-10">
                <Stack direction="row" spacing={2}>
                    <nav className="px-12">
                        <Button color="inherit">
                            <Link className="text-dr-cyan" href="/">
                            <p className={spaceGrotesk.className}>
                            Home
                            </p>
                            </Link>
                        </Button>
                        <Button color="inherit">
                            <Link className="text-dr-cyan" href="/posts">
                            <p className={spaceGrotesk.className}>
                            ./ Posts
                            </p>
                            </Link>
                        </Button>
                        <Button color="inherit">
                            <Link className="text-dr-cyan" href="/contact">
                            <p className={spaceGrotesk.className}>
                            ./ Contact
                            </p>
                            </Link>
                        </Button>
                    </nav>
                </Stack>
            </div>
        </div>
    </div>
  );
};

export default Navbar;
