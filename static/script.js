gsap.registerPlugin(SplitText);

gsap.from(".home_content_header h1 span", {
    delay: 0.5,
    opacity: 0,
    stagger: 0.15,
    duration: 2,
    filter: "blur(8px)",
    ease: "power4.out"
})

gsap.from(".home_content_header h4", {
    y: -60,
    duration: 2,
    ease: "power4.out"
})

gsap.from(".home_content_header h5", {
    y: 60,
    duration: 2,
    ease: "power4.out"
})

gsap.from(".functions_container a", {
    y: 400,
    opacity: 0,
    duration: 1,
    ease: "power4.out"
})