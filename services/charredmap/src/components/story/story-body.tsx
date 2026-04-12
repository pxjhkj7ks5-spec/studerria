import ReactMarkdown from "react-markdown";

type StoryBodyProps = {
  body: string;
};

export function StoryBody({ body }: StoryBodyProps) {
  return (
    <div className="space-y-6 text-[15px] leading-[1.85] text-[#e0e1e6] md:text-base">
      <ReactMarkdown
        components={{
          p: ({ children }) => <p className="text-balance leading-[1.85]">{children}</p>,
          h2: ({ children }) => (
            <h2 className="pt-4 font-display text-2xl leading-tight text-white md:text-3xl">
              {children}
            </h2>
          ),
          h3: ({ children }) => (
            <h3 className="pt-2 font-display text-xl leading-tight text-white md:text-2xl">
              {children}
            </h3>
          ),
          ul: ({ children }) => <ul className="list-disc space-y-2 pl-5">{children}</ul>,
          ol: ({ children }) => <ol className="list-decimal space-y-2 pl-5">{children}</ol>,
          blockquote: ({ children }) => (
            <blockquote className="rounded-r-[24px] border-l border-[--accent-orange]/70 bg-[rgba(255,132,56,0.08)] px-5 py-4 text-white">
              {children}
            </blockquote>
          ),
        }}
      >
        {body}
      </ReactMarkdown>
    </div>
  );
}
