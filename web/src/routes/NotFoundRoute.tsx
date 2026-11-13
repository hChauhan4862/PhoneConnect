import { RouteLink } from "../components/RouteLink";

export function NotFoundRoute({ path }: { path: string }) {
  return (
    <section className="panel">
      <h1>Not found</h1>
      <p className="muted">No screen exists at {path}.</p>
      <RouteLink to="/">Devices</RouteLink>
    </section>
  );
}
