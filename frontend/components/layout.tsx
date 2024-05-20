import "/app/globals.scss";
import Navbar from "./navbar"


export default function DashboardLayout({
  children,
}: {
  children: React.ReactNode
}) {
  return (
    <>
        <Navbar />
        <main>{children}</main>
    </>
  )
}
