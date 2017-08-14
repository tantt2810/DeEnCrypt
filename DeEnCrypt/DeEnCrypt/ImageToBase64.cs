using System;
using System.Drawing;
using System.IO;
using System.Windows.Forms;
using Image = System.Drawing.Image;

namespace DeEnCrypt
{
    public static class ImageToBase64
    {
        private const int SCALE_MAX_HEIGHT = 500;
        public static Image UploadImage(out OpenFileDialog fd)
        {
            fd = new OpenFileDialog();
            fd.Filter = "Images Only | *.jpg; *.jpeg; *.png; *.gif";
            DialogResult dr = fd.ShowDialog();
            Image image = Image.FromFile(fd.FileName);
            return image;
        }

        public static string GetImageBase64(Image image)
        {
            Bitmap bitmap = new Bitmap(image);
            Bitmap scaleImage = ScaleImage(bitmap, SCALE_MAX_HEIGHT);
             MemoryStream stream = new MemoryStream();
            scaleImage.Save(stream, image.RawFormat);

            byte[] imageBytes = stream.ToArray();
            return Convert.ToBase64String(imageBytes);
        }

        private static Bitmap ScaleImage(Bitmap image, int maxHeight)
        {
            float ratio = (float)maxHeight / image.Height;
            if (ratio > 1)
            {
                return image;
            }

            int width = (int)(image.Width * ratio);
            int height = (int)(image.Height * ratio);
            Bitmap newImage = new Bitmap(width, height);
            using (Graphics graphic = Graphics.FromImage(newImage))
            {
                graphic.DrawImage(image, 0, 0, width, height);
            }
            return newImage;
        }

        public static int GetNewWidth(Image image, int newHeight)
        {
            float ratio = (float) newHeight / image.Height;
            float newWidth = image.Width * ratio;
            return (int)newWidth;
        }

        public static int GetNewHeight(Image image, int newWidth)
        {
            float ratio = (float)newWidth / image.Width;
            float newHeight = image.Height * ratio;
            return (int)newHeight;
        }
    }
}
