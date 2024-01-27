import "/src/index.scss";
import * as React from "react";
import { Paper, Chip, Stack, CssBaseline, Container } from "@mui/material";

interface Post {
  id: number;
  title: string;
  category: string;
  description: string;
  date: string;
}

const ArticleBox: React.FC<Post> = (props) => {
  return (
    <Paper elevation={12}>
      <h2 className="text-dr-orange font-bold pt-5 pb-2 text-2xl">
        {props.category} - {props.title}
      </h2>
      <h6 className="text-dr-purple py-1">By SolarDebris</h6>
      <h6 className="text-dr-foreground py-0 ">{props.date}</h6>
      <p className="text-dr-foreground py-7">{props.description}</p>
      <Chip
        label="Read More"
        component="a"
        href={"/blog/" + props.id}
        clickable
      />
    </Paper>
  );
};

export default ArticleBox;
