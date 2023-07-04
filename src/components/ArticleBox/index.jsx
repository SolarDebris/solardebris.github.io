import "./index.scss";
import * as React from "react";
import { Paper, Chip, Stack, CssBaseline, Container } from "@mui/material";

const ArticleBox = (props) => {
  return (
    <Paper elevation={12}>
      <h2 class="title">
        {props.category} - {props.title}
      </h2>
      <h6 class="author">By {props.author}</h6>
      <h6 class="date">{props.date}</h6>
      <p class="description">{props.description}</p>
      <Chip label="Read More" component="a" href="/blog" clickable />
    </Paper>
  );
};

export default ArticleBox;
