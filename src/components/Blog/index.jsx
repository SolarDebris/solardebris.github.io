import "./index.scss";
import Navbar from "../Navbar";
import ArticleBox from "../ArticleBox";
import { Paper, Box, Stack, CssBaseline, Container } from "@mui/material";

const Blog = () => {
  return (
    <div>
      <div class="heading">
        <h1>Blog</h1>
      </div>
      <div class="articles">
        <Box
          sx={{
            width: "60%",
            align: "center",
            margin: "0 auto",
            display: "display-box",
            flexWrap: "wrap",
            backgroundColor: "#6273a475",
            justify: "center",
            p: 2,
            "& > :not(style)": {
              m: 5,
              mr: 2,
              p: 2,
              justify: "center",
              width: "85%",
              height: "100%",
              background: "#44475a",
            },
          }}
        >
          <ArticleBox
            author="Alex Schmith"
            category="Writeups"
            title="DEFCON 31 Quals Challenges"
            description="Writeups for DEFCON 31 Quals including Open House, iFuckUp."
          />
        </Box>
      </div>
    </div>
  );
};

export default Blog;
