import { GetServerSideProps, GetStaticProps } from "next";
import React, { useEffect, useState } from "react";
import DOMPurify from "dompurify";
import "/app/globals.scss";
import "./article.scss";
import Layer from "../../components/layout.tsx";
import Tag from "../../components/tag.tsx";
import SellOutlinedIcon from "@mui/icons-material/SellOutlined";



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

interface ArticleProps {
  initialPosts: Post[];
  postId: number;
}

const Article: React.FC<ArticleProps> = ({initialPosts, postId}) => {
  const [posts, setPosts] = useState<Post[]>(initialPosts);
  const [article, setArticle] = useState<Post | null>(null);
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
  }, [initialPosts, postId]);

  useEffect(() => {
    if (Object.keys(posts).length > 0) {
      const selectedArticle = posts[postId];
      setArticle(selectedArticle || null);
    }
  }, [posts, postId]);


  if (!article) {
    console.log("Couldn't find article");
    return (
      <Layer>
        Loading...
      </Layer>
    );
  }

  let category = article.metadata.category;
  const sanitizedContent = DOMPurify.sanitize(article.content);
  const sanitizedTitle = DOMPurify.sanitize(article.metadata.title);
  const sanitizedDate = DOMPurify.sanitize(article.metadata.date);

  let categories = Array.isArray(category) ? category : [category];
  

  return (
    <Layer>
      <div className="flex justify-center p-10">
        <div className="pt-14 px-20 p-10 bg-dr-current_line/40 w-1/2 max-w-4xl h-full rounded-lg">
          <h2 className="text-dr-orange font-grotesk font-bold text-4xl flex justify-center text-center mb-4 underline underline-offset-8 decoration-2">
            {sanitizedTitle}
          </h2>
          <div className="flex justify-center px-28 pb-10">
            <SellOutlinedIcon/>
            {categories.map((category, key) => (
                <Tag key={key} name={category}/>
            ))}
          </div>

          <h6 className="text-dr-purple py-1 flex justify-center">
            By SolarDebris
          </h6>
          <h6 className="text-dr-foreground py-1 pb-7 flex justify-center">
            {sanitizedDate}
          </h6>
          <div dangerouslySetInnerHTML={{ __html: sanitizedContent }} />
        </div>
      </div>
    </Layer>
  );
};

export const getServerSideProps: GetServerSideProps = async (context) => {
  const { id } = context.params!;
  const res = await fetch("http://localhost:5000/posts");
  const posts: Post[] = await res.json();

  return {
    props: {
      initialPosts: posts,
      postId: Number(id),
    },
  };
};




export default Article;
