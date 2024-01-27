import "/src/index.scss";
import * as React from "react";
import { Link, NavLink } from "react-router-dom";
import {
  Avatar,
  AppBar,
  IconButton,
  Typography,
  Toolbar,
  Stack,
  Button,
} from "@mui/material";
import Logo from "../../assets/images/logo.jpg";

const Navbar = () => {
  const [anchorEl, setAnchorEl] = React.useState(null);
  const open = Boolean(anchorEl);
  const handleClick = (event) => {
    setAnchorEl(event.currentTarget);
  };
  const handleClose = () => {
    setAnchorEl(null);
  };

  return (
    <AppBar position="static" class="bg-dr-current_line text-dr-cyan w-full">
      <Toolbar class="flex justify-between">
        <div class="flex items-center px-6">
          <IconButton
            size="medium"
            edge="start"
            color="inherit"
            aria-label="logo"
          >
            <a href="https://github.com/SolarDebris">
              <Avatar alt="SolarDebris" src={Logo} />
            </a>
          </IconButton>
          <p class="spacemono pr-48">Alex Schmith</p>
        </div>
        <div class="flex items-center px-10">
          <Stack direction="row" spacing={2}>
            <nav>
              <Button color="inherit">
                <a class="text-dr-cyan spacemono" href="/">
                  Home
                </a>
              </Button>
              <Button color="inherit">
                <a class="text-dr-cyan spacemono" href="/blog">
                  Blog
                </a>
              </Button>
              <Button color="inherit">
                <a class="text-dr-cyan spacemono" href="/contact">
                  Contact
                </a>
              </Button>
            </nav>
          </Stack>
        </div>
      </Toolbar>
    </AppBar>
  );
};

export default Navbar;
