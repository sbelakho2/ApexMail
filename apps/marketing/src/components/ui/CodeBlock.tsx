'use client';

interface CodeBlockProps {
 code: string;
 language: string;
}

export function CodeBlock({ code, language }: CodeBlockProps) {
 return (
 <div className="code-block overflow-hidden">
 <pre className="p-4 text-[13px] leading-relaxed overflow-x-auto" style={{ WebkitOverflowScrolling: 'touch' }}>
 <code data-language={language} className="font-mono block whitespace-pre break-normal">{code}</code>
 </pre>
 </div>
 );
}
