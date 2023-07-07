import "./index.scss";
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
  Menu,
  MenuItem,
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
      <Toolbar>
        <IconButton
          size="medium"
          edge="start"
          color="inherit"
          aria-label="logo"
        >
          <Avatar alt="SolarDebris" src={Logo} />
          <a href="https://github.com/SolarDebris"></a>
        </IconButton>
        <Typography variant="h7" component="div" sx={{ flexGrow: 1 }}>
          Alex Schmith
        </Typography>

        <Stack direction="row" spacing={2}>
          <nav>
            <Button color="inherit">
              <a class="text-dr-cyan" href="/">
                Home
              </a>
            </Button>
            <Button color="inherit">
              <a class="text-dr-cyan" href="/blog">
                Blog
              </a>
            </Button>
            <Button color="inherit">
              <a class="text-dr-cyan" href="/contact">
                Contact
              </a>
            </Button>
          </nav>
        </Stack>
      </Toolbar>
    </AppBar>
  );
};

export default Navbar;
