import "./index.scss";
import { Routes, Route } from "react-router-dom";
import Home from "./components/Home";
import Contact from "./components/Contact";
import Blog from "./components/Blog";
import Article from "./components/Article";
import { useEffect, useState } from "react";

interface Post {
  id: number;
}

function App() {
  //const [posts, setPosts] = useState([]);
  const [posts, setPosts] = useState<Post[]>([]);

  useEffect(() => {
    fetch("http://www.solardebris.xyz:5000/posts", {
      method: "GET",
      headers: {
        "Content-Type": "application/json",
      },
    })
      .then((response) => response.json())
      .then((response) => setPosts(response))
      .catch((error) => console.log(error));
  }, []);

  const articles = Object.values(posts);
  console.log(articles);

  return (
    <>
      <Routes>
        <Route path="/" element={<Home />} />
        <Route path="/blog" element={<Blog />} />
        {articles.map((post) => (
          <Route
            key={post.id}
            path={`/blog/${post.id}`}
            element={<Article id={post.id} />}
          />
        ))}
        <Route path="/contact" element={<Contact />} />
      </Routes>
    </>
  );
}

export default App;
