import { useRoute } from "./lib/router";
import { CONCEPTS, DesignGallery } from "./designs/Gallery";
import { Analysis } from "./pages/Analysis";
import { Dashboard } from "./pages/Dashboard";
import { Landing } from "./pages/Landing";

// #/ landing story · #/app dashboard (#/app/new opens the upload popup) · #/a/<id> one analysis
export function App() {
  const route = useRoute();
  if (route[0] === "a" && route[1] && /^[0-9a-f]{32}$/.test(route[1])) {
    return <Analysis key={route[1]} id={route[1]} rest={route.slice(2)} />;
  }
  if (route[0] === "app") return <Dashboard openNew={route[1] === "new"} />;
  if (route[0] === "designs") {
    const concept = CONCEPTS.find((c) => c.id === route[1]);
    return concept ? <concept.View /> : <DesignGallery />;
  }
  return <Landing />;
}
