import { useRoute } from "./lib/router";
import { Analysis } from "./pages/Analysis";
import { Home } from "./pages/Home";

export function App() {
  const route = useRoute();
  if (route[0] === "a" && route[1] && /^[0-9a-f]{32}$/.test(route[1])) {
    return <Analysis key={route[1]} id={route[1]} rest={route.slice(2)} />;
  }
  return <Home />;
}
