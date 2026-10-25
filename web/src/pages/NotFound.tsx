import { A } from "@solidjs/router";
import { Button } from "~/components/ui";

export default function NotFound() {
  return (
    <div class="empty-state min-h-[60vh]">
      <h2 class="mb-2 text-[3rem] font-bold">
        404
      </h2>
      <strong>Page not found</strong>
      <p>The page you're looking for doesn't exist or has been moved.</p>
      {/* `end`: without it the router marks "/" active on every path, and the
          .active rule painted this primary button blue (ocidex-nps9.30). */}
      <Button as={A} href="/" end variant="primary" class="mt-6">
        Back to Home
      </Button>
    </div>
  );
}
