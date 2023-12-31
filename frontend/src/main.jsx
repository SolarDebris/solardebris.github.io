import React from "react";
import ReactDOM from "react-dom/client";
import "./index.scss";
import Navbar from "./components/Navbar";
import App from "./App.jsx";
import { BrowserRouter } from "react-router-dom";

const root = ReactDOM.createRoot(document.getElementById("root"));
root.render(
  <React.StrictMode>
    <Navbar />
    <BrowserRouter>
      <App />
    </BrowserRouter>
  </React.StrictMode>
);
