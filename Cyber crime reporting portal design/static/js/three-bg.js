/**
 * Three.js Interactive 3D Neon Tube Background
 * Move mouse to deflect tubes, click to randomize colors
 */
(function () {
    const canvas = document.getElementById('three-canvas');
    if (!canvas) return;

    const scene = new THREE.Scene();
    const camera = new THREE.PerspectiveCamera(75, window.innerWidth / window.innerHeight, 0.1, 1000);
    const renderer = new THREE.WebGLRenderer({ canvas, alpha: true, antialias: true });
    renderer.setSize(window.innerWidth, window.innerHeight);
    renderer.setPixelRatio(Math.min(window.devicePixelRatio, 2));
    camera.position.z = 30;

    // Color palettes
    const palettes = [
        [0x00f5ff, 0xff006e, 0x8338ec, 0x3a86ff, 0xfb5607],
        [0x06d6a0, 0xef476f, 0xffd166, 0x118ab2, 0x073b4c],
        [0x7209b7, 0x3a0ca3, 0x4361ee, 0x4cc9f0, 0xf72585],
        [0x00b4d8, 0x0077b6, 0x90e0ef, 0xfca311, 0xe5383b],
    ];
    let currentPalette = 0;

    function getColor() {
        const p = palettes[currentPalette];
        return p[Math.floor(Math.random() * p.length)];
    }

    // Mouse tracking
    const mouse = { x: 0, y: 0, worldX: 0, worldY: 0 };

    document.addEventListener('mousemove', (e) => {
        mouse.x = (e.clientX / window.innerWidth) * 2 - 1;
        mouse.y = -(e.clientY / window.innerHeight) * 2 + 1;
        mouse.worldX = mouse.x * 25;
        mouse.worldY = mouse.y * 15;
    });

    document.addEventListener('click', () => {
        currentPalette = (currentPalette + 1) % palettes.length;
        tubes.forEach(t => {
            const c = getColor();
            t.material.color.setHex(c);
            t.material.emissive.setHex(c);
            if (t.light) t.light.color.setHex(c);
        });
    });

    // Create neon tubes
    const tubes = [];
    const tubeCount = 25;

    function createTube() {
        const points = [];
        const segments = 6;
        const startX = (Math.random() - 0.5) * 60;
        const startY = (Math.random() - 0.5) * 40;
        const startZ = (Math.random() - 0.5) * 30 - 10;

        for (let i = 0; i < segments; i++) {
            points.push(new THREE.Vector3(
                startX + (Math.random() - 0.5) * 15,
                startY + (Math.random() - 0.5) * 15,
                startZ + (Math.random() - 0.5) * 10
            ));
        }

        const curve = new THREE.CatmullRomCurve3(points);
        const geometry = new THREE.TubeGeometry(curve, 40, 0.08 + Math.random() * 0.12, 8, false);
        const color = getColor();

        const material = new THREE.MeshBasicMaterial({
            color: color,
            transparent: true,
            opacity: 0.6 + Math.random() * 0.4,
        });
        material.emissive = new THREE.Color(color);

        const mesh = new THREE.Mesh(geometry, material);

        // Add glow point light for some tubes
        if (Math.random() > 0.5) {
            const light = new THREE.PointLight(color, 0.5, 15);
            light.position.copy(points[Math.floor(segments / 2)]);
            scene.add(light);
            mesh.light = light;
        }

        mesh.originalPoints = points.map(p => p.clone());
        mesh.curve = curve;
        mesh.basePoints = points;
        mesh.speed = 0.2 + Math.random() * 0.8;
        mesh.phase = Math.random() * Math.PI * 2;

        scene.add(mesh);
        tubes.push(mesh);
    }

    for (let i = 0; i < tubeCount; i++) createTube();

    // Ambient light
    scene.add(new THREE.AmbientLight(0x111122, 0.5));

    // Animation loop
    function animate() {
        requestAnimationFrame(animate);
        const time = performance.now() * 0.001;

        tubes.forEach((tube) => {
            // Organic movement
            tube.basePoints.forEach((point, i) => {
                const orig = tube.originalPoints[i];
                point.x = orig.x + Math.sin(time * tube.speed + tube.phase + i) * 1.5;
                point.y = orig.y + Math.cos(time * tube.speed * 0.7 + tube.phase + i * 0.5) * 1.0;

                // Mouse deflection
                const dx = point.x - mouse.worldX;
                const dy = point.y - mouse.worldY;
                const dist = Math.sqrt(dx * dx + dy * dy);
                if (dist < 10) {
                    const force = (10 - dist) / 10;
                    point.x += dx * force * 0.3;
                    point.y += dy * force * 0.3;
                }
            });

            // Rebuild tube geometry
            const newCurve = new THREE.CatmullRomCurve3(tube.basePoints);
            const newGeometry = new THREE.TubeGeometry(newCurve, 40, 0.08 + Math.random() * 0.04, 8, false);
            tube.geometry.dispose();
            tube.geometry = newGeometry;

            // Update light position
            if (tube.light) {
                const mid = tube.basePoints[Math.floor(tube.basePoints.length / 2)];
                tube.light.position.lerp(mid, 0.1);
            }
        });

        // Slow camera rotation
        camera.position.x = Math.sin(time * 0.05) * 2;
        camera.position.y = Math.cos(time * 0.03) * 1;
        camera.lookAt(0, 0, 0);

        renderer.render(scene, camera);
    }
    animate();

    // Resize handler
    window.addEventListener('resize', () => {
        camera.aspect = window.innerWidth / window.innerHeight;
        camera.updateProjectionMatrix();
        renderer.setSize(window.innerWidth, window.innerHeight);
    });
})();
