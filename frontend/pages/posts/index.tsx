import GetStaticProps from "next";
import GetServerSideProps from "next";
import localFont from 'next/font/local';
import React, { useEffect, useState } from "react";
import DOMPurify from "dompurify";
import "./article.scss";
import Layer from "../../components/layout.tsx";
import ArticleBox from "../../components/article_box.tsx";
import { Box }from "@mui/material";

interface Post {
  id: number;
  metadata: Metadata;
  content: string;
}

interface Metadata {
  category: string | string[];
  date: string;
  description: string;
  title: string;
}

interface PostsProps {
  initialPosts: Post[];
}

const spaceGrotesk = localFont({
    src: '../../public/fonts/SpaceGrotesk-Regular.ttf',
    display: 'swap',
})

export async function  getStaticProps() {
  const res = await fetch("http://localhost:5000/posts");
  const posts: Post[] = await res.json();

  return {
    props: {
      initialPosts: posts
    },
  };
};



const Posts: React.FC<PostsProps> = ({ initialPosts }) => {
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
  console.log(articles);

  console.log("Tags");
  console.log(articles[0].metadata.category);

  return (
    <Layer>
        <div className="flex justify-center pt-10 pb-10">
          <div className="pt-14 bg-dr-current_line/40 w-3/5 h-full rounded-lg max-w-4xl">
            <div className="text-5xl text-dr-red font-grotesk font-bold p-10 pb-5 flex justify-center">
              <h1 className={spaceGrotesk.className}>Posts</h1>
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
                      key={index}
                      metadata={post.metadata}
                      content={post.content}
                      id={index}
                    />
                ))}
            </Box>
          </div>
        </div>

    </Layer>
  );
};


export default Posts;
