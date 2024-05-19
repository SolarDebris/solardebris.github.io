import "/app/globals.scss";
import * as React from "react";
import { Paper, Chip, Stack, CssBaseline, Container } from "@mui/material";
import DOMPurify from "dompurify";
import Tag from "/components/tag.tsx";
import SellOutlinedIcon from '@mui/icons-material/SellOutlined';

interface Post {
  id: string;
  metadata: Metadata;
  content: string;
}

interface Metadata {
  category: string;
  date: string;
  description: string;
  title: string;
}

const ArticleBox: React.FC<Post> = (props) => {

  //const sanitized_category = DOMPurify.sanitize(props.metadata.category);
  //const sanitized_title = DOMPurify.sanitize(props.metadata.title);
  //const sanitized_date = DOMPurify.sanitize(props.metadata.date);
  //const sanitized_description = DOMPurify.sanitize(props.metadata.description);
  console.log(props);

  return (
    <Paper elevation={12}>
      <h2  className="text-dr-orange font-bold pt-5 pb-2 text-2xl underline mb-4 underline-offset-8 decoration-2">
        <a href={"/posts/" + props.id}>
            {props.metadata.title}
        </a>
      </h2>
      <div className="flex px-28 justify-center">
        <SellOutlinedIcon/>
        {props.metadata.category.map((category) => (
            <Tag name={category}/>
        ))}
      </div>
      <h6 className="text-dr-purple py-1">By SolarDebris</h6>
      <h6 className="text-dr-foreground py-0 ">{props.metadata.date}</h6>
      <p className="text-dr-foreground py-7">{props.metadata.description}</p>
      <Chip
        label="Read More"
        component="a"
        href={"/posts/" + props.id}
        clickable
      />
    </Paper>
  );
};

export default ArticleBox;
