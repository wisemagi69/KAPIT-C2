package org.kapit.c2.mobile.ui

import androidx.compose.foundation.layout.size
import androidx.compose.material3.Icon
import androidx.compose.material3.LocalContentColor
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.SolidColor
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.graphics.StrokeJoin
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.graphics.vector.PathParser
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.dp

/**
 * Stroke icons drawn from the same 24x24 path data as the website's icon set (web/src/icons.tsx),
 * so both clients share one visual language without an extra icon dependency.
 */
internal enum class KapitIcon(vararg val paths: String) {
    HOME("M3 3h7v7H3z", "M14 3h7v7h-7z", "M3 14h7v7H3z", "M14 14h7v7h-7z"),
    OUTBOX("M4 14v6h16v-6", "M12 4v11", "m8 8 4-4 4 4"),
    REPORT("M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z", "M14 2v6h6", "M8 13h8", "M8 17h5"),
    ACCOUNT("M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2", "M12 3a4 4 0 1 0 0 8 4 4 0 0 0 0-8"),
    LOCK("M5 10h14v11H5z", "M8 10V7a4 4 0 0 1 8 0v3"),
    SHIELD("M12 2 3 6v6c0 5 9 10 9 10s9-5 9-10V6z", "m8 12 3 3 5-6"),
    PLUS("M12 5v14", "M5 12h14"),
    REFRESH("M20 7v5h-5", "M4 17v-5h5", "M6 6a8 8 0 0 1 13 2l1 4", "M18 18a8 8 0 0 1-13-2l-1-4"),
    ALERT("m12 3 10 18H2z", "M12 9v5", "M12 17v.01"),
    CHECK("m5 12 4 4L19 6"),
    ;

    val vector: ImageVector by lazy {
        val builder = ImageVector.Builder(name, 24.dp, 24.dp, 24f, 24f)
        paths.forEach { data ->
            builder.addPath(PathParser().parsePathString(data).toNodes(), fill = null, stroke = SolidColor(Color.Black),
                strokeLineWidth = 1.7f, strokeLineCap = StrokeCap.Round, strokeLineJoin = StrokeJoin.Round)
        }
        builder.build()
    }
}

/** Decorative by default: the adjacent text label carries the meaning for accessibility services. */
@Composable
internal fun KapitIconView(icon: KapitIcon, modifier: Modifier = Modifier, size: Dp = 22.dp,
                           tint: Color = LocalContentColor.current, contentDescription: String? = null) {
    Icon(icon.vector, contentDescription, modifier.size(size), tint = tint)
}

