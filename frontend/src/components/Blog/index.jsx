import "./index.scss";
import Navbar from "../Navbar";
import ArticleBox from "../ArticleBox";
import { Paper, Box, Stack, CssBaseline, Container } from "@mui/material";

const Blog = () => {
  const articles = [
    {
      category: "writeup",
      title: "DEFCON 31 Quals Challenges",
      date: "June 10th, 2023",
      description:
        "A retroactive writeup on some of the pwn and re challenges. Including Open-House and I Fuck Up",
    },
    {
      category: "writeup",
      title: "Google CTF 2023 Quals Challenges",
      date: "June 30th, 2023",
      description:
        "A retroactive writeup on some of the pwn and re challenges. Including the write-what-where, kconcat, and a few others",
    },
    {
      category: "writeup",
      title: "UIUCTF 2023 Challenges",
      date: "July 5th, 2023",
      description:
        "A retroactive writeup on some of the pwn and re challenges. Including mock-kernel, virophage",
    },
  ];

  return (
    <div class="flex justify-center pt-10 pb-10">
      <div class="pt-14 bg-dr-current_line/40 w-3/5 h-full rounded-lg">
        <div class="text-5xl text-dr-red font-bold p-10 flex justify-center">
          <h1>Blog</h1>
        </div>
        <Box
          sx={{
            p: 2,
            "& > :not(style)": {
              m: 5,
              p: 3,
              justify: "center",
              width: "90%",
              height: "100%",
              background: "#44475a",
            },
          }}
        >
          {articles.map((article, index) => (
            <ArticleBox key={index} {...article} />
          ))}
        </Box>
      </div>
    </div>
  );
};

export default Blog;
