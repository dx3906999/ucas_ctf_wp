cd _book
git init
git add .
git commit -m "update"
git remote add github https://github.com/dx3906999/ucas_ctf_wp.git
git branch gh-pages
git checkout gh-pages
git push -u github gh-pages
echo "done"