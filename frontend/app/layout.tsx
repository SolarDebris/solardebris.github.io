import "/app/globals.scss";
import Navbar from "../components/navbar"


export default function RootLayout({
  children,
}: {
  children: React.ReactNode
}) {
  return (
    <html lang="en">
      <body>        
        <main>{children}</main>
      </body>
    </html>
  )
}
