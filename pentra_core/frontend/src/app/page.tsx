import { redirect } from "next/navigation"

export default function Home() {
    // In a real app we would check auth here
    redirect("/login")
}
