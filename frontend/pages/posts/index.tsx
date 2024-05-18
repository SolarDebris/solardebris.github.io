
import { GetServerSideProps } from "next";
import React, { useEffect, useState } from "react";
import DOMPurify from "dompurify";
import "/app/globals.scss";
import "./article.scss";
import Layer from "/components/layout.tsx";
import ArticleBox from "/components/article_box.tsx";
import Box from "@mui/material";

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

interface ArticleProps {
  initialPosts: Post[];
  postId: string;
}

const Article: React.FC<ArticleProps> = ({ initialPosts }) => {
  const [posts, setPosts] = useState<Post[]>(initialPosts);
useEffect(() => { if (initialPosts.length === 0) {
      fetch("http://localhost:5000/posts", {
        method: "GET",
        headers: {
          "Content-Type": "application/json",
        },
      })
        .then((response) => response.json())
        .then((response) => setPosts(response))
        .catch((error) => console.log(error));
    }
  }, [initialPosts]);

  const articles = Object.values(posts);

  return (
    <Layer>

        <div className="flex justify-center pt-10 pb-10">
          <div className="pt-14 bg-dr-current_line/40 w-3/5 h-full rounded-lg max-w-7xl">
            <div className="text-5xl text-dr-red font-bold p-10 pb-5 flex justify-center">
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
              {articles.map((post, index) => (
                <ArticleBox
                  category={post.metadata.category}
                  title={post.metadata.title}
                  date={post.metadata.date}
                  description={post.metadata.description}
                  id={Number(index)}
                />
              ))}
            </Box>
          </div>
        </div>

    </Layer>
  );
};

export const getServerSideProps: GetServerSideProps = async (context) => {
  const res = await fetch("http://localhost:5000/posts");
  const posts: Post[] = await res.json();

  return {
    props: {
      initialPosts: posts
    },
  };
};

export default Article;
