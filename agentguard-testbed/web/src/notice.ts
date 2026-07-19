import { ApiError } from "./api";

export type Notice = { tone: "info" | "success" | "danger"; message: string } | null;

export function errorNotice(error: unknown): NonNullable<Notice> {
  if (error instanceof SyntaxError) {
    return { tone: "danger", message: "The editor contains invalid JSON." };
  }
  if (error instanceof ApiError) {
    return { tone: "danger", message: `${error.code}: ${error.message}` };
  }
  return { tone: "danger", message: "The operation could not be completed." };
}
